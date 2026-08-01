"""Signed, last-known-good revocation state.

Revocation is a *separate offline authority* from the release signer. A release key
that is compromised cannot un-revoke itself, so the snapshot is signed by
``revocation@cathedral.computer`` under its own namespace and its own root-owned
trust file (``$CATHEDRAL_REVOCATION_SIGNERS``, default ``<home>/revocation_signers``).

The snapshot binds an exact document::

    schema
    sequence                     monotonic, positive, bounded
    issued_at                    aware UTC
    expires_at                   aware UTC, after issued_at, bounded lifetime
    revoked_release_digests      exact lowercase sha256 lock digests
    revoked_signer_fingerprints  OpenSSH SHA256: fingerprints
    signer_key_id                which offline key issued it

Three properties are structural rather than merely tested:

**The cache is one file.** The snapshot and its detached signature are stored in a
single container replaced with one ``os.replace``. Two independent renames would
leave a crash window in which a new snapshot sat beside an old signature — a pair
that verifies as nothing and fails closed at the worst possible moment. One file,
one rename, no window.

**The sequence has a durable floor.** Restoring an older cache file is not enough
to roll revocation knowledge back: ``revocation-floor.json`` records the highest
sequence ever retained, is read no-follow with ownership and mode checks, and is
compared and advanced inside an exclusive transaction lock. A snapshot below the
floor is refused even though its signature is perfectly valid.

**Freshness is policy, not a boolean.** Acquiring a release and rolling one back
both claim current global knowledge, so both demand a snapshot inside its validity
window. Continuing to run an already-installed release does not: a channel outage
must degrade to offline knowledge, loudly, rather than stop a healthy node.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as _dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from cathedral_node import paths, release_lock, safeio

SNAPSHOT_SCHEMA = "cathedral.revocation.v1"
CACHE_SCHEMA = "cathedral.revocation.cache.v1"
FLOOR_SCHEMA = "cathedral.revocation_floor.v1"
NAMESPACE = "cathedral-revocation"

# The one identity a revocation snapshot must be signed as. Pinned in code and
# required in the operator's root-owned revocation trust file.
REVOCATION_IDENTITY = "revocation@cathedral.computer"

_SNAPSHOT_KEYS = {"schema", "sequence", "issued_at", "expires_at", "revoked_release_digests",
                  "revoked_signer_fingerprints", "signer_key_id"}
_CACHE_KEYS = {"schema", "snapshot", "signature"}
_FLOOR_KEYS = {"schema", "sequence", "snapshot_digest", "committed_at"}
_MAX_SEQUENCE = 2**31
_MAX_SKEW = _dt.timedelta(hours=6)
_MAX_LIFETIME = _dt.timedelta(days=400)
_MAX_ENTRIES = 100_000
_SNAPSHOT_MAX = 1 << 22  # 4 MiB
_CACHE_MAX = 1 << 23
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]*$")

# --- freshness policies ---------------------------------------------------------
#
# ACQUISITION      installing or updating to a new candidate. Claims current global
#                  knowledge, so the snapshot must be inside its validity window.
# RETAINED_RUNTIME re-verifying an already-installed release. A stale snapshot is
#                  reported, not fatal: a channel outage must not stop a healthy
#                  node, and it must never be reinterpreted as release expiry.
# ROLLBACK         offline rollback. Claims current global knowledge; fails closed
#                  outside the freshness window.
ACQUISITION = "acquisition"
RETAINED_RUNTIME = "retained_runtime"
ROLLBACK = "rollback"
_POLICIES = (ACQUISITION, RETAINED_RUNTIME, ROLLBACK)
_DEMANDS_FRESHNESS = frozenset({ACQUISITION, ROLLBACK})

_SEAL = object()


class RevocationError(Exception):
    """Revocation state could not be established. Always fail closed on this."""


class RevocationState:
    """A verified snapshot. Sealed: only :func:`verify_snapshot` builds one, so
    holding an instance is proof the offline authority signed these exact bytes."""

    __slots__ = ("sequence", "issued_at", "expires_at", "signer_key_id",
                 "_release_digests", "_signer_fingerprints", "stale", "digest")

    def __init__(self, seal: Any, *, sequence: int, issued_at: _dt.datetime,
                 expires_at: _dt.datetime, signer_key_id: str, release_digests: frozenset[str],
                 signer_fingerprints: frozenset[str], stale: bool, digest: str) -> None:
        if seal is not _SEAL:
            raise TypeError("RevocationState is produced only by revocation verification")
        object.__setattr__(self, "sequence", int(sequence))
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "signer_key_id", str(signer_key_id))
        object.__setattr__(self, "_release_digests", frozenset(release_digests))
        object.__setattr__(self, "_signer_fingerprints", frozenset(signer_fingerprints))
        object.__setattr__(self, "stale", bool(stale))
        object.__setattr__(self, "digest", str(digest))

    def __setattr__(self, *_a: Any) -> None:
        raise AttributeError("RevocationState is immutable")

    @property
    def revoked_release_digests(self) -> frozenset[str]:
        return self._release_digests

    @property
    def revoked_signer_fingerprints(self) -> frozenset[str]:
        return self._signer_fingerprints

    def is_release_revoked(self, lock_digest: str) -> bool:
        return str(lock_digest).lower() in self._release_digests

    def revoked_signers(self, fingerprints: set[str]) -> set[str]:
        return set(fingerprints) & self._signer_fingerprints

    def to_dict(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "issued_at": self.issued_at.isoformat(),
                "expires_at": self.expires_at.isoformat(), "signer_key_id": self.signer_key_id,
                "revoked_release_digests": sorted(self._release_digests),
                "revoked_signer_fingerprints": sorted(self._signer_fingerprints),
                "stale": self.stale, "snapshot_digest": self.digest}


# --- signer fingerprints -------------------------------------------------------

def signer_fingerprints(allowed_signers: str, identity: str) -> set[str]:
    """The OpenSSH ``SHA256:`` fingerprints an ``allowed_signers`` file binds to
    ``identity``. Computed in-process from the base64 key blob — no subprocess, so
    revocation checking works with no external tool and no ambient environment."""
    found: set[str] = set()
    for line in (allowed_signers or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 3:
            continue
        principals = fields[0].split(",")
        if identity not in principals:
            continue
        try:
            blob = base64.b64decode(fields[2], validate=True)
        except (ValueError, TypeError):
            continue
        found.add("SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="))
    return found


# --- strict snapshot verification ----------------------------------------------

def _aware(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _exact_str_set(value: Any, pattern: re.Pattern[str]) -> frozenset[str] | None:
    if not isinstance(value, list) or len(value) > _MAX_ENTRIES:
        return None
    if any(not isinstance(x, str) or not pattern.match(x) for x in value):
        return None
    if len(set(value)) != len(value):
        return None
    return frozenset(value)


def verify_snapshot(raw: bytes, signature: bytes, allowed_signers: str, *,
                    now: _dt.datetime, identity: str = REVOCATION_IDENTITY,
                    ) -> tuple[bool, str, RevocationState | None]:
    """Verify the offline authority's signature over these exact bytes and parse the
    exact document. Expiry is *reported* (``stale``), never silently accepted and
    never conflated with release-manifest expiry."""
    if now.tzinfo is None:
        return False, "the verifying clock is not timezone-aware", None
    if not raw or len(raw) > _SNAPSHOT_MAX:
        return False, "the revocation snapshot is empty or oversized", None
    if not release_lock.verify_detached_signature(raw, signature, allowed_signers, identity,
                                                  NAMESPACE):
        return False, "the revocation snapshot signature did not verify", None
    try:
        document = release_lock.parse_strict(raw)
    except ValueError as exc:
        return False, f"the revocation snapshot is malformed: {exc}", None
    if set(document.keys()) != _SNAPSHOT_KEYS:
        return False, "the revocation snapshot has an unknown or missing field", None
    if document["schema"] != SNAPSHOT_SCHEMA:
        return False, "the revocation snapshot schema is unrecognised", None
    sequence = document["sequence"]
    if not (isinstance(sequence, int) and not isinstance(sequence, bool)
            and 1 <= sequence <= _MAX_SEQUENCE):
        return False, "the revocation sequence is not a positive bounded integer", None
    issued = _aware(document["issued_at"])
    expires = _aware(document["expires_at"])
    if issued is None or expires is None:
        return False, "revocation timestamps must be aware UTC", None
    if issued > now + _MAX_SKEW:
        return False, "the revocation snapshot is issued too far in the future", None
    if expires <= issued:
        return False, "the revocation snapshot expiry is not after its issue", None
    if expires - issued > _MAX_LIFETIME:
        return False, "the revocation snapshot lifetime exceeds the maximum", None
    digests = _exact_str_set(document["revoked_release_digests"], _HEX64_RE)
    if digests is None:
        return False, "revoked_release_digests must be unique lowercase sha256 digests", None
    fingerprints = _exact_str_set(document["revoked_signer_fingerprints"], _FINGERPRINT_RE)
    if fingerprints is None:
        return False, "revoked_signer_fingerprints must be unique SHA256: fingerprints", None
    key_id = document["signer_key_id"]
    if not (isinstance(key_id, str) and _TOKEN_RE.match(key_id)):
        return False, "the revocation signer_key_id is malformed", None
    state = RevocationState(_SEAL, sequence=sequence, issued_at=issued, expires_at=expires,
                            signer_key_id=key_id, release_digests=digests,
                            signer_fingerprints=fingerprints, stale=(now >= expires),
                            digest=hashlib.sha256(raw).hexdigest())
    return True, "ok", state


# --- the retained last-known-good cache ----------------------------------------

def cache_dir() -> Path:
    return paths.engines_dir() / "revocation"


def cache_file() -> Path:
    """The single container holding the snapshot **and** its signature.

    One file, so one ``os.replace`` swaps the pair. Two files could be swapped only
    by two renames, and a crash between them leaves a snapshot beside a signature
    that does not cover it.
    """
    return cache_dir() / "cache.json"


def floor_file() -> Path:
    return paths.engines_dir() / "revocation-floor.json"


def transaction_lock() -> Path:
    return paths.engines_dir() / "revocation.lock"


def _encode_cache(raw: bytes, signature: bytes) -> bytes:
    return json.dumps({"schema": CACHE_SCHEMA,
                       "snapshot": base64.b64encode(raw).decode("ascii"),
                       "signature": base64.b64encode(signature).decode("ascii")},
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def _decode_cache(data: bytes) -> tuple[bytes, bytes] | None:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict) or set(document.keys()) != _CACHE_KEYS:
        return None
    if document["schema"] != CACHE_SCHEMA:
        return None
    try:
        return (base64.b64decode(document["snapshot"], validate=True),
                base64.b64decode(document["signature"], validate=True))
    except (ValueError, TypeError):
        return None


def _read_cache() -> tuple[bool, tuple[bytes, bytes] | None, str]:
    ok, data, reason = safeio.secure_read(cache_file(), limit=_CACHE_MAX)
    if not ok:
        return False, None, f"the revocation cache is untrustworthy: {reason}"
    if data is None:
        return True, None, "no cached signed revocation state is retained"
    pair = _decode_cache(data)
    if pair is None:
        return False, None, "the revocation cache container is malformed"
    return True, pair, "ok"


# --- the durable, monotonic sequence floor --------------------------------------

def _read_floor() -> tuple[bool, tuple[int, str] | None, str]:
    """``(ok, (sequence, snapshot_digest), reason)``. ``None`` means never retained."""
    ok, data, reason = safeio.secure_read(floor_file(), limit=1 << 16)
    if not ok:
        return False, None, f"the revocation floor is untrustworthy: {reason}"
    if data is None:
        return True, None, "ok"
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, None, "the revocation floor is corrupt"
    if not isinstance(document, dict) or set(document.keys()) != _FLOOR_KEYS:
        return False, None, "the revocation floor has an unknown or missing field"
    if document["schema"] != FLOOR_SCHEMA:
        return False, None, "the revocation floor schema is unrecognised"
    sequence = document["sequence"]
    if not (isinstance(sequence, int) and not isinstance(sequence, bool)
            and 1 <= sequence <= _MAX_SEQUENCE):
        return False, None, "the revocation floor sequence is not a positive bounded integer"
    digest = document["snapshot_digest"]
    if not (isinstance(digest, str) and _HEX64_RE.match(digest)):
        return False, None, "the revocation floor digest is not a lowercase sha256 digest"
    if _aware(document["committed_at"]) is None:
        return False, None, "the revocation floor committed_at is not aware UTC"
    return True, (sequence, digest), "ok"


def _write_floor(sequence: int, digest: str) -> None:
    safeio.secure_write_atomic(floor_file(), json.dumps({
        "schema": FLOOR_SCHEMA, "sequence": sequence, "snapshot_digest": digest,
        "committed_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }, sort_keys=True, indent=2).encode("utf-8") + b"\n")


def floor_state() -> tuple[bool, tuple[int, str] | None, str]:
    """The revocation sequence floor, for reporting and for tests."""
    return _read_floor()


# --- reading and retaining -------------------------------------------------------

def _trust(trust_path: Path | None) -> tuple[bool, str, str | None]:
    ok, reason, allowed = release_lock.read_trust_file(trust_path or paths.revocation_signers())
    if not ok or allowed is None:
        return False, f"revocation trust root: {reason}", None
    if not _names_identity(allowed, REVOCATION_IDENTITY):
        return False, f"the revocation trust root does not authorize {REVOCATION_IDENTITY}", None
    return True, "ok", allowed


def _names_identity(allowed_signers: str, identity: str) -> bool:
    for line in allowed_signers.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and identity in stripped.split()[0].split(","):
            return True
    return False


_FLOOR_ADVANCED = "the floor advanced past this snapshot"


def load_retained(*, now: _dt.datetime, trust_path: Path | None = None, heal: bool = False,
                  _attempt: int = 0,
                  ) -> tuple[bool, str, RevocationState | None]:
    """The last known good snapshot, read and verified entirely offline.

    The durable sequence floor is enforced here, not only at retention time: a
    cache file restored from a backup, or swapped in by anything with write access,
    is refused if it is below the highest sequence this node has ever accepted.

    ``heal`` closes the gap left by a crash between the two publications. The cache
    and the floor are separate files, so a crash after the cache lands and before
    the floor does leaves a node whose retained snapshot is *ahead* of its floor.
    That state is not corrupt — the higher snapshot verified and is durably on disk
    — but leaving the floor behind means the older snapshot the floor still names
    would be accepted again if someone restored it. So the public read paths
    advance the floor to what the cache has durably proven. It only ever raises,
    and it is idempotent, which is why doing it on a read is safe.
    """
    tok, treason, allowed = _trust(trust_path)
    if not tok or allowed is None:
        return False, treason, None
    cok, pair, creason = _read_cache()
    if not cok or pair is None:
        return False, creason, None
    ok, reason, state = verify_snapshot(pair[0], pair[1], allowed, now=now)
    if not ok or state is None:
        return False, reason, None
    fok, floor, freason = _read_floor()
    if not fok:
        return False, freason, None
    if floor is not None:
        if state.sequence < floor[0]:
            return False, (f"the retained revocation snapshot (sequence {state.sequence}) is below "
                           f"the durable revocation floor ({floor[0]}); it was rolled back"), None
        if state.sequence == floor[0] and state.digest != floor[1]:
            return False, ("a different revocation snapshot claims the sequence recorded in the "
                           "durable revocation floor"), None
    if heal and (floor is None or floor[0] < state.sequence):
        healed, detail = _heal_floor(state, trust_path)
        if detail == _FLOOR_ADVANCED:
            # A concurrent transaction moved the floor past this snapshot while we
            # were healing. Returning `state` now would hand the caller a snapshot
            # BELOW the durable floor — the exact inversion the floor exists to
            # prevent — so the read starts again against the state that won.
            if _attempt >= 2:
                return False, ("the revocation floor kept advancing while the retained snapshot "
                               "was being read"), None
            return load_retained(now=now, trust_path=trust_path, heal=heal, _attempt=_attempt + 1)
        if not healed:
            # The cache is ahead of the floor and the floor could not be advanced.
            # Returning success here was the defect: the caller would be authorized
            # on sequence 11 while the *durable* rollback protection still said 9,
            # so restoring the sequence 9 cache would re-admit it. Rollback
            # protection that is only in memory is not rollback protection.
            return False, (f"the retained revocation snapshot (sequence {state.sequence}) is ahead "
                           f"of the durable floor and the floor could not be advanced: {detail}"), \
                None
    return True, "ok", state


def _heal_floor(state: "RevocationState", trust_path: Path | None) -> tuple[bool, str]:
    """Advance a lagging floor to what the retained cache has durably proven.

    Re-read under the transaction lock before writing: between the read that
    noticed the lag and this write, a concurrent `retain` may already have moved
    the floor past this snapshot, and lowering it would be precisely the rollback
    the floor exists to prevent.
    """
    try:
        with safeio.secure_lock(transaction_lock(), exclusive=True, timeout=30.0,
                                busy_message="another revocation transaction holds the lock"):
            ok, floor, reason = _read_floor()
            if not ok:
                return False, reason
            if floor is not None and floor[0] > state.sequence:
                # Somebody else won. Reporting "healed" here was the defect: the
                # caller would be handed sequence 11 while the durable floor said
                # 12, so a snapshot the node has already refused would be treated
                # as current for the rest of that operation.
                return False, _FLOOR_ADVANCED
            if floor is not None and floor[0] == state.sequence and floor[1] != state.digest:
                return False, ("a different revocation snapshot claims this sequence in the "
                               "durable floor")
            if floor is None or floor[0] < state.sequence:
                _write_floor(state.sequence, state.digest)
            return True, "healed"
    except safeio.SecureOpenError as exc:
        return False, str(exc)
    except OSError as exc:
        return False, f"the revocation floor could not be written: {exc}"


def retain(raw: bytes, signature: bytes, *, now: _dt.datetime, trust_path: Path | None = None,
           ) -> tuple[bool, str, RevocationState | None]:
    """Atomically retain ``raw`` only if it verifies and is strictly newer.

    Held under the revocation transaction lock so a concurrent refresh cannot
    interleave a compare with a write. The container and the floor are each written
    with a single ``os.replace``; the container goes first, so a crash between them
    leaves a valid newer cache under an older floor — which the next read accepts —
    rather than a floor that refuses the only cache on disk.
    """
    trust = trust_path or paths.revocation_signers()
    tok, treason, allowed = _trust(trust)
    if not tok or allowed is None:
        return False, treason, None
    try:
        with safeio.secure_lock(transaction_lock(), exclusive=True, timeout=60.0,
                                busy_message='another revocation transaction is in progress'):
            return _retain_locked(raw, signature, allowed, now=now, trust_path=trust)
    except safeio.SecureOpenError as exc:
        return False, f"the revocation transaction lock is unusable: {exc}", None


def _retain_locked(raw: bytes, signature: bytes, allowed: str, *, now: _dt.datetime,
                   trust_path: Path) -> tuple[bool, str, RevocationState | None]:
    vok, vreason, candidate = verify_snapshot(raw, signature, allowed, now=now)
    current = _current(now, trust_path)
    if not vok or candidate is None:
        return False, vreason, current
    fok, floor, freason = _read_floor()
    if not fok:
        return False, freason, current
    floor_sequence, floor_digest = (floor if floor is not None else (0, ""))
    # The cache's OWN sequence, verified without reference to the floor. `current`
    # is the floor-filtered view, which is None precisely when the two disagree —
    # so using it here would hide the disagreement this comparison exists to find.
    cache_sequence, cache_digest = _cache_identity(allowed, now)
    highest = max(floor_sequence, cache_sequence)

    # The digest to compare against belongs to whichever file actually holds the
    # highest sequence. Always preferring the floor's digest was the defect: after
    # a crash between the cache write and the floor write, cache 11 sits above
    # floor 9, and an identical sequence-11 retry was compared against the
    # sequence-9 digest, rejected as a conflict, and never reached the floor write
    # that would have healed it. The node then stayed one crash away from accepting
    # sequence 9 again, forever.
    if floor_sequence == highest and cache_sequence == highest and floor_digest != cache_digest:
        return False, ("the revocation floor and the retained cache both claim sequence "
                       f"{highest} with different digests; refusing to guess which is authentic"), \
            current
    known_digest = floor_digest if floor_sequence == highest else cache_digest

    if candidate.sequence < highest:
        return False, (f"revocation sequence {candidate.sequence} is older than the retained "
                       f"{highest}; the last known good snapshot is kept"), current
    if candidate.sequence == highest and highest:
        if candidate.digest != known_digest:
            # Refused BEFORE any healing side effect: a different snapshot at the
            # retained sequence is a forgery attempt, and must not be able to move
            # the floor on its way to being rejected.
            return False, ("a different revocation snapshot claims the retained sequence; the last "
                           "known good snapshot is kept"), current
        if floor_sequence < highest:
            # The identical snapshot, retried after a partial commit. This is the
            # retry healing the floor, which is exactly what it is for.
            _write_floor(candidate.sequence, candidate.digest)
            return True, "healed the lagging revocation floor", candidate
        if cache_digest != candidate.digest:
            # The mirror image: the floor is at the highest sequence but the cache
            # is not. Reporting "already current" while the only cache on disk is a
            # stale snapshot the floor now refuses left the node with no usable
            # revocation state at all — a success that produced nothing. The
            # candidate IS the signed state the floor names, so write it.
            safeio.secure_write_atomic(cache_file(), _encode_cache(raw, signature))
            return True, "restored the signed snapshot the durable floor names", candidate
        return True, "already current", current
    safeio.secure_write_atomic(cache_file(), _encode_cache(raw, signature))
    _write_floor(candidate.sequence, candidate.digest)
    return True, "retained", candidate


def _cache_identity(allowed: str, now: _dt.datetime) -> tuple[int, str]:
    """The retained cache's own (sequence, digest), floor comparison deliberately
    excluded. Used only to decide which file holds the highest sequence."""
    cok, pair, _reason = _read_cache()
    if not cok or pair is None:
        return 0, ""
    ok, _reason, state = verify_snapshot(pair[0], pair[1], allowed, now=now)
    return (state.sequence, state.digest) if (ok and state is not None) else (0, "")


def _current(now: _dt.datetime, trust: Path, *, heal: bool = False) -> RevocationState | None:
    """The retained state, for a caller that already knows which lock it holds.

    ``heal`` defaults to false because the in-transaction callers hold the
    transaction lock already, and healing takes the same lock — `flock` is per open
    file description, so a second acquisition from this process would block against
    itself. A caller *outside* the lock must pass ``heal=True``: exporting a
    snapshot that is ahead of the durable floor authorizes it on protection that
    does not survive a restart.
    """
    ok, _reason, state = load_retained(now=now, trust_path=trust, heal=heal)
    return state if ok else None


# --- fetching (inert bytes only) ------------------------------------------------

def refresh(channel_base: str | None, *, now: _dt.datetime,
            fetch: Callable[[str, int], bytes] | None = None,
            trust_path: Path | None = None) -> tuple[bool, str, RevocationState | None]:
    """Try to advance the cache from the channel, then report the effective state.

    An unreachable or hostile channel is not an error the caller must treat as
    fatal: the retained snapshot stays authoritative and is returned. What is fatal
    — enforced by the caller for acquisition — is having *no* verified snapshot, or
    one outside its validity window.
    """
    trust = trust_path or paths.revocation_signers()
    if channel_base:
        getter = fetch or _http_fetch
        base = channel_base.rstrip("/")
        try:
            raw = getter(f"{base}/revocation.json", _SNAPSHOT_MAX)
            signature = getter(f"{base}/revocation.json.sig", _SNAPSHOT_MAX)
        except Exception as exc:  # noqa: BLE001 - any transport failure degrades to cache
            # Degrading to the cache is legitimate. Degrading to a cache that is
            # ahead of the durable floor is not: the floor is what stops the older
            # snapshot being re-admitted after a restart, so it must be advanced
            # here or the outage must be reported as having no usable state.
            current = _current(now, trust, heal=True)
            detail = f"the revocation channel is unavailable ({type(exc).__name__}); using the cache"
            if current is None:
                detail = (f"the revocation channel is unavailable ({type(exc).__name__}) and the "
                          f"retained snapshot is not usable")
            return (current is not None), detail, current
        ok, reason, state = retain(raw, signature, now=now, trust_path=trust)
        if ok:
            return True, reason, state
        # The channel answered, and what it said was not usable: invalid bytes, an
        # older sequence, or a different digest at the sequence we already hold.
        # Falling back to the cache is right, but `retain` returns the state it
        # *read*, which may be ahead of the durable floor — and exporting that is
        # the same defect as exporting it on an outage. There is exactly one way to
        # produce an effective state here, and it is the floored read.
        current = _current(now, trust, heal=True)
        if current is None:
            return False, (f"{reason}; and the retained snapshot is not usable"), None
        return True, f"{reason}; using the retained snapshot", current
    return load_retained(now=now, trust_path=trust, heal=True)


def _http_fetch(url: str, limit: int) -> bytes:
    import urllib.parse
    import urllib.request
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "file") and not (
            parsed.scheme == "http" and (parsed.hostname or "") in ("127.0.0.1", "::1", "localhost")):
        raise ValueError(f"refusing a non-HTTPS revocation URL: {url}")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - scheme gated above
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("the revocation snapshot exceeds its size limit")
    return data


# --- enforcement ----------------------------------------------------------------

def enforce(lock_digest: str, release_allowed_signers: str, release_identity: str, *,
            now: _dt.datetime, policy: str, trust_path: Path | None = None,
            ) -> tuple[bool, str, RevocationState | None]:
    """The offline check every lifecycle decision runs.

    Fails closed when there is no verified cache, when the release digest is
    revoked, when the release signer's key is revoked, and — for the policies that
    claim current global knowledge — when the snapshot is outside its freshness
    window.
    """
    if policy not in _POLICIES:
        return False, f"unknown revocation policy {policy!r}", None
    ok, reason, state = load_retained(now=now, trust_path=trust_path, heal=True)
    if not ok or state is None:
        return False, f"revocation state: {reason}", None
    if state.is_release_revoked(lock_digest):
        return False, "the release digest is revoked by signed revocation state", state
    revoked = state.revoked_signers(signer_fingerprints(release_allowed_signers, release_identity))
    if revoked:
        return False, f"the release signer key is revoked ({sorted(revoked)[0]})", state
    if policy in _DEMANDS_FRESHNESS and state.stale:
        return False, (f"the retained revocation snapshot expired at "
                       f"{state.expires_at.isoformat()}; {policy} requires current revocation "
                       f"knowledge and will not proceed on stale state"), state
    return True, ("ok" if not state.stale else "ok (revocation knowledge is stale)"), state


def status(*, now: _dt.datetime, trust_path: Path | None = None) -> dict[str, Any]:
    """An explicit report of what the node knows and how old it is."""
    ok, reason, state = load_retained(now=now, trust_path=trust_path)
    report: dict[str, Any] = {"available": bool(ok and state is not None), "detail": reason}
    fok, floor, freason = _read_floor()
    report["floor_sequence"] = floor[0] if (fok and floor) else None
    report["floor_detail"] = freason
    if state is not None:
        report.update(state.to_dict())
    return report


def canonical_snapshot(*, sequence: int, issued_at: str, expires_at: str,
                       revoked_release_digests: list[str], revoked_signer_fingerprints: list[str],
                       signer_key_id: str) -> bytes:
    """Canonical bytes for a snapshot. Used by the offline authority's tooling and
    by tests; the node itself only ever verifies, it never issues."""
    return release_lock.canonical_bytes({
        "schema": SNAPSHOT_SCHEMA, "sequence": sequence, "issued_at": issued_at,
        "expires_at": expires_at, "revoked_release_digests": sorted(revoked_release_digests),
        "revoked_signer_fingerprints": sorted(revoked_signer_fingerprints),
        "signer_key_id": signer_key_id})


def install_cache(raw: bytes, signature: bytes, *, now: _dt.datetime | None = None,
                  trust_path: Path | None = None) -> RevocationState:
    """Provision the retained snapshot — through the one verified transaction.

    This used to write the cache before verifying anything, without the
    transaction lock, and advance the floor on ``sequence >= floor``. Every one of
    those is a way to lose the property the floor exists for: unverified bytes
    became "the last known good snapshot"; two concurrent provisions interleaved a
    compare with a write; ``>=`` let a *different* digest overwrite the floor at
    the same sequence; and with no lock a slow writer could lower a floor another
    caller had already raised.

    Provisioning is not a special case that gets to skip the transaction. It is
    just a retention whose caller expects it to succeed, so a refusal raises rather
    than being returned and ignored.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    ok, reason, state = retain(raw, signature, now=now, trust_path=trust_path)
    if not ok or state is None:
        raise RevocationError(f"the revocation snapshot could not be provisioned: {reason}")
    return state


__all__ = ["SNAPSHOT_SCHEMA", "CACHE_SCHEMA", "FLOOR_SCHEMA", "NAMESPACE", "REVOCATION_IDENTITY",
           "ACQUISITION", "RETAINED_RUNTIME", "ROLLBACK", "RevocationError", "RevocationState",
           "verify_snapshot", "load_retained", "retain", "refresh", "enforce", "status",
           "signer_fingerprints", "canonical_snapshot", "cache_file", "floor_file",
           "floor_state", "install_cache", "transaction_lock"]
