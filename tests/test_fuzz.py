from __future__ import annotations

import random
import unittest

from oes32_membrane_shield import (
    WIDTH,
    Action,
    AuthorizationError,
    CapabilityIssuer,
    CapabilityVerifier,
    MembraneShield,
    OES32State,
    Role,
    Sector,
    boundary_payload,
    calibration_payload,
)


class EndToEndIntegrationTests(unittest.TestCase):
    def test_full_independent_authority_lifecycle(self) -> None:
        now = [10_000]
        decoder = CapabilityIssuer.generate("decoder-v2", "decoder-service", Role.DECODEUR)
        guardian = CapabilityIssuer.generate("guardian-v2", "guardian-operator", Role.GARDIEN)
        calibrator = CapabilityIssuer.generate(
            "calibrator-v2", "calibrator-operator", Role.CALIBRATEUR
        )
        observer = CapabilityIssuer.generate("observer-v2", "observer-service", Role.OBSERVATEUR)
        verifier = CapabilityVerifier(
            {
                decoder.key_id: decoder.authority_key(),
                guardian.key_id: guardian.authority_key(),
                calibrator.key_id: calibrator.authority_key(),
                observer.key_id: observer.authority_key(),
            },
            clock=lambda: now[0],
        )
        shield = MembraneShield(verifier, tau=0.25, sector=Sector.ANY)

        reference = OES32State.create([0.05] * WIDTH, [0.05] * WIDTH)
        approvals = (
            calibrator.issue(
                Action.CALIBRATE, calibration_payload(reference), now=now[0], request_id="cal-1"
            ),
            guardian.issue(
                Action.CALIBRATE, calibration_payload(reference), now=now[0], request_id="cal-2"
            ),
        )
        shield.calibrate(*approvals, reference)
        self.assertEqual(shield.state, reference)

        observer_capability = observer.issue(Action.OBSERVE, now=now[0], request_id="observe-1")
        self.assertEqual(shield.observe(observer_capability), reference)

        boundary = list(reference.boundary)
        boundary[3] += 0.1
        write = decoder.issue(
            Action.WRITE, boundary_payload(boundary), now=now[0], request_id="write-1"
        )
        result = shield.request_flip(write, boundary)
        self.assertTrue(result.admitted)
        self.assertAlmostEqual(result.state.boundary[3], 0.15)
        self.assertEqual(len(shield.audit_events()), 4)

        breach = list(boundary)
        breach[0] += 1.0
        breach_capability = decoder.issue(
            Action.WRITE, boundary_payload(breach), now=now[0], request_id="write-breach"
        )
        self.assertFalse(shield.request_flip(breach_capability, breach).admitted)
        self.assertTrue(shield.latched)
        reset = guardian.issue(Action.WRITE, b"reset", now=now[0], request_id="reset-1")
        shield.reset(reset)
        self.assertFalse(shield.latched)

    def test_independent_pair_rejects_same_subject_even_with_different_keys(self) -> None:
        first = CapabilityIssuer.generate("cal-a", "same-operator", Role.CALIBRATEUR)
        second = CapabilityIssuer.generate("guard-a", "same-operator", Role.GARDIEN)
        verifier = CapabilityVerifier(
            {first.key_id: first.authority_key(), second.key_id: second.authority_key()},
            clock=lambda: 1_000,
        )
        state = OES32State.zeros()
        a = first.issue(Action.CALIBRATE, calibration_payload(state), now=1_000, request_id="a")
        b = second.issue(Action.CALIBRATE, calibration_payload(state), now=1_000, request_id="b")
        with self.assertRaises(AuthorizationError):
            verifier.verify_independent_pair(
                a, b, action=Action.CALIBRATE, payload=calibration_payload(state)
            )


class DeterministicFuzzTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rng = random.Random(0x0E532)
        self.issuer = CapabilityIssuer.generate("fuzz-decoder", "fuzz", Role.DECODEUR)
        self.guardian = CapabilityIssuer.generate("fuzz-guardian", "fuzz-guardian", Role.GARDIEN)
        self.verifier = CapabilityVerifier(
            {
                self.issuer.key_id: self.issuer.authority_key(),
                self.guardian.key_id: self.guardian.authority_key(),
            },
            clock=lambda: 50_000,
        )
        self.shield = MembraneShield(self.verifier, tau=10.0, sector=Sector.ANY)

    def test_random_bounded_vectors_never_corrupt_state(self) -> None:
        for index in range(1_000):
            before = self.shield.state
            size = self.rng.randrange(0, WIDTH + 8)
            boundary = [self.rng.uniform(-1.0, 1.0) for _ in range(size)]
            if size == WIDTH and self.rng.random() < 0.1:
                boundary[self.rng.randrange(WIDTH)] = float("nan")
            capability = self.issuer.issue(
                Action.WRITE,
                boundary_payload([0.0] * WIDTH),
                now=50_000,
                request_id=f"fuzz-{index}",
            )
            result = self.shield.request_flip(capability, boundary)
            self.assertIsInstance(result.admitted, bool)
            if not result.admitted:
                self.assertEqual(self.shield.state, before)

    def test_random_byte_capabilities_fail_closed(self) -> None:
        for index in range(500):
            size = self.rng.randrange(0, 256)
            data = self.rng.randbytes(size)
            try:
                capability = type(
                    self.issuer.issue(Action.OBSERVE, request_id=f"parse-{index}")
                ).from_bytes(data)
            except AuthorizationError:
                continue
            with self.assertRaises(AuthorizationError):
                self.verifier.verify(capability, action=Action.OBSERVE, role=Role.OBSERVATEUR)

    def test_mutated_signed_capabilities_never_authorize_substituted_payload(self) -> None:
        original = [0.1] + [0.0] * (WIDTH - 1)
        substituted = [0.2] + [0.0] * (WIDTH - 1)
        for index in range(200):
            capability = self.issuer.issue(
                Action.WRITE,
                boundary_payload(original),
                now=50_000,
                request_id=f"mutate-{index}",
            )
            result = self.shield.request_flip(capability, substituted)
            self.assertFalse(result.admitted)
            self.assertEqual(self.shield.state, OES32State.zeros())

    def test_expiry_boundary_and_clock_skew(self) -> None:
        issuer = CapabilityIssuer.generate("expiry", "expiry-test", Role.DECODEUR)
        verifier = CapabilityVerifier(
            {issuer.key_id: issuer.authority_key()}, clock=lambda: 1_005, max_clock_skew_seconds=0
        )
        capability = issuer.issue(
            Action.OBSERVE, now=1_000, lifetime_seconds=5, request_id="expires-now"
        )
        with self.assertRaises(AuthorizationError):
            verifier.verify(capability, action=Action.OBSERVE, role=Role.DECODEUR)


if __name__ == "__main__":
    unittest.main()
