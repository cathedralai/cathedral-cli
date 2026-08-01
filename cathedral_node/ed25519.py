"""A minimal, self-contained Ed25519 (RFC 8032) — standard library only.

The node is zero-dependency by design, so it cannot import a crypto library. This
vendors the RFC 8032 reference (public domain) so a signed release lock can be
verified — and, for tests and an owner-held authority, signed — without adding a
dependency. It uses only ``hashlib`` and integer arithmetic and is exercised
against a known-answer round trip in the test suite.

Scope: authorizing an update's exact dependency set and artifact hashes. Never
used for chain writes, wallet material, or transport secrecy. The reference is
correct but not constant-time; that is acceptable here because it verifies a
public release manifest, not a secret.
"""

from __future__ import annotations

import hashlib

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_d * y * y + 1, _q - 2, _q)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * pow(5, _q - 2, _q)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + denom, _q - 2, _q)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - denom, _q - 2, _q)
    return (x3 % _q, y3 % _q)


def _scalarmult(P, e: int):
    result = (0, 1)
    addend = P
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << (_b - 1))).to_bytes(_b // 8, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _secret_scalar(h: bytes) -> int:
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def _hint(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed (private key)."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _secret_scalar(_sha512(seed))
    return _encodepoint(_scalarmult(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = _secret_scalar(h)
    A = _encodepoint(_scalarmult(_B, a))
    r = _hint(h[_b // 8:_b // 4] + message)
    R = _encodepoint(_scalarmult(_B, r))
    S = (r + _hint(R + A + message) * a) % _L
    return R + _encodeint(S)


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoded point is not on the curve")
    return P


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid Ed25519 signature of ``message``."""
    if len(signature) != _b // 4 or len(public) != _b // 8:
        return False
    try:
        R = _decodepoint(signature[:_b // 8])
        A = _decodepoint(public)
    except (ValueError, OverflowError):
        return False
    S = int.from_bytes(signature[_b // 8:_b // 4], "little")
    if S >= _L:
        return False
    h = _hint(signature[:_b // 8] + public + message)
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
