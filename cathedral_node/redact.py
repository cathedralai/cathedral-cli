"""Keeping secrets out of everything we emit.

Applied to engine output before it reaches a log file, the terminal, or a JSON
envelope. It is a backstop, not the primary defence — the primary defence is
that secrets are only ever passed through the environment and are never asked
for on a command line. This catches an engine that prints one anyway.

Two rules learned from getting it wrong:

* Order matters. A general ``key: value`` rule that runs before the
  ``Bearer <token>`` rule consumes the word "Bearer" as the value and leaves the
  actual token in the clear.
* Masking by key name must be precise. A key called ``secrets`` holding a list
  of secret *names* is safe to print; blanking it because the word "secret"
  appears loses information without protecting anything.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "[redacted]"

_SENSITIVE_WORD = (
    r"(?:api[_-]?key|secret|token|password|passwd|seed|mnemonic"
    r"|private[_-]?key|bearer|authorization|credential|coldkey)"
)


def _mask_key_value(match: re.Match[str]) -> str:
    quote = match.group("open")
    return f"{match.group('key')}{match.group('sep')}{quote}{MASK}{quote}"


_PATTERNS: tuple[tuple[re.Pattern[str], Any], ...] = (
    # PEM blocks first — they span lines and would confuse every other rule.
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "-----BEGIN PRIVATE KEY----- " + MASK + " -----END PRIVATE KEY-----",
    ),
    # Auth schemes before the generic key/value rule, so "Bearer" is recognised
    # as part of the scheme rather than swallowed as the value.
    (re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=\-]{8,})"), r"\1 " + MASK),
    # key = value / "key": "value" / key: value, with an optionally quoted key.
    (
        re.compile(
            r"""(?ix)
            (?P<key> ["']? [A-Za-z0-9_.\-]* """
            + _SENSITIVE_WORD
            + r""" [A-Za-z0-9_.\-]* ["']? )
            (?P<sep> \s* [:=] \s* )
            (?P<open> ["']? )
            (?P<val> [^\s"',;}\]]{4,} )
            (?P=open)
            """
        ),
        _mask_key_value,
    ),
    # Credentials inside a URL. `user:pass@host` is the standard way a key ends
    # up in an endpoint, and it carries no adjacent key name to match on.
    (re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*://)([^\s/:@]+):([^\s/@]+)@"), r"\1\2:" + MASK + "@"),
    # Provider key formats that are recognisable by shape alone. `sk-` is the
    # dominant OpenAI-compatible prefix and this product's default endpoint is
    # OpenAI-compatible, so a bare one appearing in engine output is likely real.
    (re.compile(r"\b(sk|rk|pk|ghp|gho|xoxb|xoxp)[-_][A-Za-z0-9_\-]{16,}\b"), MASK),
    # Long hex that is plausibly key material. sha256:-prefixed digests are
    # deliberately preserved: they are public identifiers an operator needs.
    (re.compile(r"(?<![:\w])(?<!sha256:)\b[0-9a-fA-F]{64,}\b"), MASK),
)

# Keys whose *values* are always masked in structured output. Matched against
# the whole key, not as a substring, so `secrets` (a container of names) and
# `secrets_file` (a path) stay readable while `api_key` does not.
_SECRET_KEY = re.compile(
    r"(?i)^(?:[a-z0-9]+[_-])*" + _SENSITIVE_WORD + r"(?:[_-](?:value|hex|b64|base64|raw))?$"
)

# Explicitly safe even though they contain a sensitive word. Each is a name, a
# path, a count, a flag, or a fingerprint — never the material itself.
_SAFE_KEYS = frozenset(
    {
        "secrets",
        "secrets_file",
        "secret_store",
        "api_key_secret",
        "bearer_token_secret",
        "bearer_token_env",
        "secrets_supplied",
        "is_secret_reference",
        "requires_credentials",
        "never_accepted",
        "coldkey_refused",
    }
)


# Literal secret values this process is holding. Pattern matching can only ever
# guess; the node *knows* these strings, because it just read them out of the
# store to build a child environment. Registering them turns redaction from
# "does this look like a secret" into "is this the secret", which is the only
# form that catches a bare token printed with no adjacent key name, or one
# embedded in a URL's userinfo.
_KNOWN_VALUES: set[str] = set()

# Literal values the node knows are PUBLIC — the inverse of the above. The
# backstop masks anything 64-hex-shaped, which also matches a 32-byte *public*
# key. The validator's `weight_policy_key` is exactly that: a public key the
# operator is explicitly told to read and verify independently. Masking it in the
# machine interface (while the terminal shows it in full) both broke JSON/human
# parity and hid the operator's own signing-key control. Registering the exact
# value says "this is known-public; never mask it", without weakening masking of
# anything else.
_KNOWN_PUBLIC_VALUES: set[str] = set()

# Below this length a "secret" is more likely to appear by accident in ordinary
# output than to be the credential, and masking it would corrupt the log.
_MIN_TRACKED_LENGTH = 8


def register_secret_values(values) -> None:
    """Track literal secret values so they are masked wherever they appear.

    Called with whatever this invocation resolved for an engine. Values are held
    in memory for the life of the process only; nothing is written anywhere.
    """
    for value in values or ():
        text = str(value)
        if len(text) >= _MIN_TRACKED_LENGTH:
            _KNOWN_VALUES.add(text)


def forget_secret_values() -> None:
    _KNOWN_VALUES.clear()


def register_public_values(values) -> None:
    """Track literal values known to be public so the shape heuristics never mask
    them. Used for declared-public config fields (e.g. the weight-policy key),
    which are safe to read aloud by design."""
    for value in values or ():
        text = str(value)
        # Never let a value already known to be secret be registered as public.
        # redact_value enforces this at emit time too; this is the belt to that
        # suspenders, independent of registration order.
        if len(text) >= _MIN_TRACKED_LENGTH and text not in _KNOWN_VALUES:
            _KNOWN_PUBLIC_VALUES.add(text)


def forget_public_values() -> None:
    _KNOWN_PUBLIC_VALUES.clear()


# Control characters that let untrusted text drive the terminal: C0 (other than
# tab/newline), DEL, and the C1 block U+0080-U+009F (which includes the 8-bit CSI
# U+009B — an escape-free way to inject a control sequence). Stripped from
# everything we redact, so nothing reaches the terminal or a log.
_CONTROL_STRIP = {c: None for c in range(0x20) if c not in (0x09, 0x0a)}
_CONTROL_STRIP[0x7f] = None
_CONTROL_STRIP.update({c: None for c in range(0x80, 0xA0)})
_CONTROL_TABLE = str.maketrans(_CONTROL_STRIP)


def sanitize_controls(text: str) -> str:
    return text.translate(_CONTROL_TABLE)


def redact_text(text: str) -> str:
    """Mask secret-looking substrings in free text and strip control characters.

    Known literal values go first: an exact match is certain, so it should not
    depend on a pattern also happening to fire.
    """
    if not text:
        return text
    out = text
    # Longest first, so a secret that contains another is fully masked.
    for value in sorted(_KNOWN_VALUES, key=len, reverse=True):
        if value in out:
            out = out.replace(value, MASK)
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return sanitize_controls(out)


def redact_value(value: Any, *, key: str | None = None) -> Any:
    """Recursively mask a JSON-ish structure.

    A value is masked when its key names a credential, whatever the value's
    shape, so a nested credential object cannot leak field by field.
    """
    if key is not None and key.lower() not in _SAFE_KEYS and _SECRET_KEY.match(key):
        return MASK
    if isinstance(value, dict):
        # Redact keys too: a mapping key is emitted verbatim and could itself carry
        # a secret or control characters.
        return {redact_text(str(k)): redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        # Known-secret status always wins: a value registered as both secret and
        # public must still be masked, never emitted in full.
        if value in _KNOWN_PUBLIC_VALUES and value not in _KNOWN_VALUES:
            return sanitize_controls(value)
        return redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # An opaque value: stringify AND redact it, so nothing bypasses masking by not
    # being a recognised JSON type.
    return redact_text(str(value))


def fingerprint(secret: str) -> str:
    """A stable, non-reversible label so an operator can tell two keys apart.

    Shows only a hash prefix — never any character of the secret itself, because
    a leading prefix of a real key is still key material.
    """
    import hashlib

    if not secret:
        return "empty"
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:12]} ({len(secret)} chars)"
