"""Ed25519 encoding checks applied before signature verification.

``cryptography`` (OpenSSL) verifies Ed25519 signatures with the cofactorless
equation but does not reject small-order public keys. With a small-order
authority key (for example the identity point ``01 00 .. 00`` or the
all-zero encoding), a fixed signature whose ``R`` is the identity and whose
``S`` is zero verifies for *every* message. These helpers reject such keys
when an :class:`AuthorityKey` is created and reject small-order ``R`` values
in signatures, in the spirit of libsodium's strict checks.

Pure Python, edwards25519 parameters from RFC 8032 section 5.1.
"""

from __future__ import annotations

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int]
IDENTITY: Point = (0, 1)


def decode_point(encoded: bytes) -> Point | None:
    """Decode a 32-byte point; return ``None`` if non-canonical or not on the curve."""

    if not isinstance(encoded, (bytes, bytearray)) or len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= P:
        return None  # non-canonical y
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None  # x = 0 encoded with the sign bit set: non-canonical
        return (0, y)
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None  # not on the curve
    if (x & 1) != sign:
        x = P - x
    return (x, y)


def _add(a: Point, b: Point) -> Point:
    x1, y1 = a
    x2, y2 = b
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return (x3, y3)


def is_small_order(point: Point) -> bool:
    """True if ``[8]point`` is the identity (the point has order 1, 2, 4 or 8)."""

    q = point
    for _ in range(3):
        q = _add(q, q)
    return q == IDENTITY


def is_acceptable_public_key(encoded: bytes) -> bool:
    """Canonical, on the curve, and not of small order."""

    point = decode_point(encoded)
    return point is not None and not is_small_order(point)


def has_acceptable_r(signature: bytes) -> bool:
    """64-byte signature whose ``R`` is canonical, on the curve and not of small order,
    and whose ``S`` is below the group order."""

    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    if int.from_bytes(signature[32:], "little") >= L:
        return False
    return is_acceptable_public_key(bytes(signature[:32]))
