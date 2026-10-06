"""Regression tests: small-order / non-canonical Ed25519 keys and signatures are rejected.

Before this fix a verifier configured with a small-order authority key (identity point,
all-zero encoding, order-2 point, ...) accepted the fixed signature R = identity, S = 0
for every message, because OpenSSL's Ed25519 verification does not reject small-order
public keys.
"""

from __future__ import annotations

import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oes32_membrane_shield import (
    Action,
    AuthorityKey,
    AuthorizationError,
    CapabilityIssuer,
    CapabilityVerifier,
    Role,
    SignedCapability,
)
from oes32_membrane_shield._ed25519 import (
    decode_point,
    has_acceptable_r,
    is_acceptable_public_key,
    is_small_order,
)

# The eight points of order 1, 2, 4 or 8 in canonical encoding.
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
]
NON_CANONICAL = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1
    "0100000000000000000000000000000000000000000000000000000000000080",  # x = 0 with sign bit
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # x = 0 with sign bit
]
NOW = 1_800_000_000
PAYLOAD = b"proposal-bytes"
UNIVERSAL_SIGNATURE = bytes.fromhex(SMALL_ORDER[0]) + b"\0" * 32  # R = identity, S = 0


def forged(key_id: str, role: Role, signature: bytes) -> SignedCapability:
    return SignedCapability(
        key_id=key_id,
        subject="attacker",
        role=role,
        action=Action.WRITE,
        request_id="forged-1",
        payload_digest=hashlib.sha256(PAYLOAD).hexdigest(),
        issued_at=NOW,
        expires_at=NOW + 60,
        signature=signature,
    )


class WeakKeyTests(unittest.TestCase):
    def test_small_order_points_are_detected(self) -> None:
        for hexkey in SMALL_ORDER:
            point = decode_point(bytes.fromhex(hexkey))
            self.assertIsNotNone(point, hexkey)
            assert point is not None
            self.assertTrue(is_small_order(point), hexkey)

    def test_authority_key_rejects_small_order_keys(self) -> None:
        for hexkey in SMALL_ORDER:
            with self.assertRaises(AuthorizationError, msg=hexkey):
                AuthorityKey("mock", Role.DECODEUR, bytes.fromhex(hexkey))

    def test_authority_key_rejects_non_canonical_and_malformed_keys(self) -> None:
        bad = [bytes.fromhex(h) for h in NON_CANONICAL]
        bad += [b"", b"\x01" * 31, b"\x01" * 33, bytes.fromhex("02" + "00" * 31)]
        for key in bad:
            with self.assertRaises(AuthorizationError, msg=key.hex()):
                AuthorityKey("mock", Role.DECODEUR, key)
        with self.assertRaises(AuthorizationError):
            AuthorityKey("mock", Role.DECODEUR, bytearray(32))  # type: ignore[arg-type]

    def test_generated_keys_are_accepted(self) -> None:
        for _ in range(16):
            issuer = CapabilityIssuer.generate("k", "s", Role.DECODEUR)
            key = issuer.authority_key()
            self.assertTrue(is_acceptable_public_key(key.public_key))

    def test_universal_forgery_with_small_order_key_is_refused(self) -> None:
        # Regression for the pre-fix forgery: the verifier could not be configured with the key.
        for hexkey in SMALL_ORDER[:3]:
            with self.assertRaises(AuthorizationError):
                CapabilityVerifier(
                    {"mock": AuthorityKey("mock", Role.DECODEUR, bytes.fromhex(hexkey))},
                    clock=lambda: NOW,
                )

    def test_small_order_r_is_refused_before_verification(self) -> None:
        issuer = CapabilityIssuer.generate("decoder-key", "decoder", Role.DECODEUR)
        verifier = CapabilityVerifier({"decoder-key": issuer.authority_key()}, clock=lambda: NOW)
        for hexkey in SMALL_ORDER + NON_CANONICAL:
            sig = bytes.fromhex(hexkey) + b"\0" * 32
            self.assertFalse(has_acceptable_r(sig))
            with self.assertRaisesRegex(AuthorizationError, "invalid capability signature"):
                verifier.verify(
                    forged("decoder-key", Role.DECODEUR, sig),
                    action=Action.WRITE,
                    role=Role.DECODEUR,
                    payload=PAYLOAD,
                )

    def test_signature_shape_checks(self) -> None:
        key = Ed25519PrivateKey.generate()
        good = key.sign(b"message")
        self.assertTrue(has_acceptable_r(good))
        self.assertFalse(has_acceptable_r(good[:63]))
        too_big_s = good[:32] + (2**253).to_bytes(32, "little")
        self.assertFalse(has_acceptable_r(too_big_s))
        self.assertFalse(has_acceptable_r(UNIVERSAL_SIGNATURE))

    def test_valid_capabilities_still_verify(self) -> None:
        issuer = CapabilityIssuer.generate("decoder-key", "decoder", Role.DECODEUR)
        verifier = CapabilityVerifier({"decoder-key": issuer.authority_key()}, clock=lambda: NOW)
        cap = issuer.issue(Action.WRITE, PAYLOAD, request_id="ok-1", now=NOW)
        self.assertIs(
            verifier.verify(cap, action=Action.WRITE, role=Role.DECODEUR, payload=PAYLOAD), cap
        )


if __name__ == "__main__":
    unittest.main()
