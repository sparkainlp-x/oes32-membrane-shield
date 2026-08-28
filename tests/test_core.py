from __future__ import annotations

import contextlib
import io
import math
import sys
import unittest
from unittest.mock import patch

from oes32_membrane_shield import (
    WIDTH,
    Action,
    AuthorizationError,
    CapabilityIssuer,
    CapabilityVerifier,
    LoopDenied,
    MembraneShield,
    OES32State,
    Role,
    Sector,
    boundary_payload,
    calibration_payload,
    fast_residual_max,
    format_monte_carlo_report,
    run_monte_carlo,
)


def authorities() -> tuple[dict[str, object], dict[Role, CapabilityIssuer]]:
    issuers = {
        Role.OBSERVATEUR: CapabilityIssuer.generate("observer-key", "alice", Role.OBSERVATEUR),
        Role.DECODEUR: CapabilityIssuer.generate("decoder-key", "decoder-service", Role.DECODEUR),
        Role.CALIBRATEUR: CapabilityIssuer.generate(
            "calibrator-key", "operator-a", Role.CALIBRATEUR
        ),
        Role.GARDIEN: CapabilityIssuer.generate("guardian-key", "operator-b", Role.GARDIEN),
    }
    keys = {issuer.key_id: issuer.authority_key() for issuer in issuers.values()}
    return keys, issuers


class MembraneShieldTests(unittest.TestCase):
    def setUp(self) -> None:
        keys, self.issuers = authorities()
        self.verifier = CapabilityVerifier(keys, clock=lambda: 1_000)
        self.shield = MembraneShield(self.verifier, tau=0.5)
        self.decoder = self.issuers[Role.DECODEUR]
        self.observer = self.issuers[Role.OBSERVATEUR]
        self.calibrator = self.issuers[Role.CALIBRATEUR]
        self.guardian = self.issuers[Role.GARDIEN]

    def write_capability(self, boundary: list[float], *, issuer: CapabilityIssuer | None = None):
        return (issuer or self.decoder).issue(
            Action.WRITE,
            boundary_payload(boundary),
            now=1_000,
            request_id="write-" + str(id(boundary)),
        )

    def test_observation_requires_external_capability(self) -> None:
        authorization = self.observer.issue(Action.OBSERVE, now=1_000, request_id="observe-1")
        state = self.shield.observe(authorization)
        self.assertEqual(state, OES32State.zeros())
        self.assertFalse(hasattr(self.shield, "issue_token"))
        self.assertFalse(hasattr(self.shield, "_secrets"))

    def test_observer_cannot_write(self) -> None:
        boundary = [0.0] * WIDTH
        result = self.shield.request_flip(
            self.write_capability(boundary, issuer=self.observer), boundary
        )
        self.assertFalse(result.admitted)
        self.assertIn("denied write access", result.reason)

    def test_valid_flip_updates_bulk_and_boundary(self) -> None:
        boundary = [0.1 if index == 0 else 0.0 for index in range(WIDTH)]
        result = self.shield.request_flip(self.write_capability(boundary), boundary)
        self.assertTrue(result.admitted)
        self.assertEqual(result.state.boundary[0], 0.1)
        self.assertEqual(result.state.bulk[0], 0.1)

    def test_payload_binding_prevents_substitution(self) -> None:
        approved = [0.1] + [0.0] * (WIDTH - 1)
        substituted = [0.2] + [0.0] * (WIDTH - 1)
        result = self.shield.request_flip(self.write_capability(approved), substituted)
        self.assertFalse(result.admitted)
        self.assertIn("payload mismatch", result.reason)

    def test_capability_replay_is_rejected(self) -> None:
        boundary = [0.0] * WIDTH
        authorization = self.write_capability(boundary)
        self.assertTrue(self.shield.request_flip(authorization, boundary).admitted)
        replay = self.shield.request_flip(authorization, boundary)
        self.assertFalse(replay.admitted)
        self.assertIn("replayed", replay.reason)

    def test_expired_capability_is_rejected(self) -> None:
        authorization = self.decoder.issue(
            Action.WRITE, boundary_payload([0.0] * WIDTH), now=900, lifetime_seconds=10
        )
        result = self.shield.request_flip(authorization, [0.0] * WIDTH)
        self.assertFalse(result.admitted)
        self.assertIn("expired", result.reason)

    def test_residual_breach_latches_and_preserves_state(self) -> None:
        boundary = [1.5] + [0.0] * (WIDTH - 1)
        result = self.shield.request_flip(self.write_capability(boundary), boundary)
        self.assertFalse(result.admitted)
        self.assertTrue(self.shield.latched)
        self.assertEqual(self.shield.state, OES32State.zeros())

    def test_reset_requires_guardian_capability_and_is_audited(self) -> None:
        boundary = [1.5] + [0.0] * (WIDTH - 1)
        self.shield.request_flip(self.write_capability(boundary), boundary)
        bad_reset = self.decoder.issue(Action.WRITE, b"reset", now=1_000, request_id="reset-bad")
        with self.assertRaises(LoopDenied):
            self.shield.reset(bad_reset)
        good_reset = self.guardian.issue(Action.WRITE, b"reset", now=1_000, request_id="reset-good")
        self.shield.reset(good_reset)
        self.assertFalse(self.shield.latched)
        self.assertEqual(self.shield.audit_events()[-1].reason, "reset")

    def test_health_checks_are_enforced(self) -> None:
        proposal = [0.1] + [0.0] * (WIDTH - 1)
        result = self.shield.request_flip(
            self.write_capability(proposal), proposal, syndrome_ok=False
        )
        self.assertEqual(result.reason, "syndrome rejected")

    def test_bad_vectors_are_rejected_without_mutation(self) -> None:
        for proposal in ([0.0] * 16, ["x"] * WIDTH, [math.nan] * WIDTH):
            authorization = self.decoder.issue(
                Action.WRITE,
                boundary_payload([0.0] * WIDTH),
                now=1_000,
                request_id="bad-" + str(id(proposal)),
            )
            result = self.shield.request_flip(authorization, proposal)  # type: ignore[arg-type]
            self.assertFalse(result.admitted)
            self.assertEqual(self.shield.state, OES32State.zeros())

    def test_even_odd_and_fold8_symmetry(self) -> None:
        even = MembraneShield(self.verifier, tau=0.5, sector=Sector.EVEN)
        even_boundary = [0.0] * WIDTH
        even_boundary[0] = even_boundary[16] = 0.2
        self.assertTrue(
            even.request_flip(self.write_capability(even_boundary), even_boundary).admitted
        )

        odd = MembraneShield(self.verifier, tau=0.5, sector=Sector.ODD)
        odd_boundary = [0.0] * WIDTH
        odd_boundary[0], odd_boundary[16] = 0.2, -0.2
        self.assertTrue(
            odd.request_flip(self.write_capability(odd_boundary), odd_boundary).admitted
        )

        fold8 = MembraneShield(self.verifier, tau=0.5, sector=Sector.FOLD8)
        fold_boundary = [0.2] * WIDTH
        self.assertTrue(
            fold8.request_flip(self.write_capability(fold_boundary), fold_boundary).admitted
        )

    def test_dual_control_requires_distinct_authorities_and_binds_reference(self) -> None:
        reference = OES32State.create([0.1] * WIDTH, [0.1] * WIDTH)
        first = self.calibrator.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-a"
        )
        second = self.guardian.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-b"
        )
        self.shield.calibrate(first, second, reference)
        self.assertEqual(self.shield.state, reference)

        same_authority = self.calibrator.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-c"
        )
        with self.assertRaises(LoopDenied):
            self.shield.calibrate(same_authority, same_authority, reference)

        # A failed pair does not consume the valid first approval.
        valid_first = self.calibrator.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-f"
        )
        invalid_second = self.calibrator.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-g"
        )
        with self.assertRaises(LoopDenied):
            self.shield.calibrate(valid_first, invalid_second, reference)
        valid_second = self.guardian.issue(
            Action.CALIBRATE, calibration_payload(reference), now=1_000, request_id="cal-h"
        )
        self.shield.calibrate(valid_first, valid_second, reference)

    def test_capability_round_trip_and_tamper_detection(self) -> None:
        capability = self.decoder.issue(
            Action.WRITE, boundary_payload([0.0] * WIDTH), now=1_000, request_id="round-trip"
        )
        self.assertEqual(
            self.verifier.verify(
                type(capability).from_bytes(capability.to_bytes()),
                action=Action.WRITE,
                role=Role.DECODEUR,
                payload=boundary_payload([0.0] * WIDTH),
            ),
            capability,
        )
        tampered = capability.to_bytes().replace(b"decoder-service", b"attacker--------")
        with self.assertRaises(AuthorizationError):
            self.verifier.verify(
                type(capability).from_bytes(tampered),
                action=Action.WRITE,
                role=Role.DECODEUR,
                payload=boundary_payload([0.0] * WIDTH),
            )

    def test_dual_control_rejects_mismatched_reference(self) -> None:
        first_reference = OES32State.create([0.1] * WIDTH, [0.1] * WIDTH)
        second_reference = OES32State.create([0.2] * WIDTH, [0.2] * WIDTH)
        first = self.calibrator.issue(
            Action.CALIBRATE, calibration_payload(first_reference), now=1_000, request_id="cal-d"
        )
        second = self.guardian.issue(
            Action.CALIBRATE, calibration_payload(first_reference), now=1_000, request_id="cal-e"
        )
        with self.assertRaises(LoopDenied):
            self.shield.calibrate(first, second, second_reference)

    def test_audit_events_do_not_contain_private_credentials(self) -> None:
        boundary = [0.0] * WIDTH
        authorization = self.write_capability(boundary)
        self.shield.request_flip(authorization, boundary)
        events = self.shield.audit_events()
        self.assertNotIn(authorization.signature.hex(), repr(events))
        self.assertEqual(events[-1].subject, "decoder-service")

    def test_input_and_constructor_validation(self) -> None:
        with self.assertRaises(ValueError):
            MembraneShield(self.verifier, epsilon=-1)
        with self.assertRaises(ValueError):
            CapabilityVerifier({}, clock=lambda: 1_000)
        with self.assertRaises(AuthorizationError):
            self.verifier.verify("bad", action=Action.OBSERVE, role=Role.OBSERVATEUR)  # type: ignore[arg-type]
        with self.assertRaises(LoopDenied):
            self.shield.observe(
                self.decoder.issue(Action.OBSERVE, now=1_000, request_id="wrong-role")
            )
        with self.assertRaises(ValueError):
            fast_residual_max((1.0,), ())
        with self.assertRaises(LoopDenied):
            OES32State.create([math.nan] * WIDTH, [0.0] * WIDTH)


class SimulationTests(unittest.TestCase):
    def test_seed_makes_counts_reproducible(self) -> None:
        first = run_monte_carlo(iterations=50, seed=7)
        second = run_monte_carlo(iterations=50, seed=7)
        for key in (
            "total_cycles",
            "admitted",
            "rejected_residual",
            "rejected_symmetry",
            "latched_count",
        ):
            self.assertEqual(first[key], second[key])

    def test_zero_iteration_report_and_validation(self) -> None:
        report = format_monte_carlo_report(run_monte_carlo(iterations=0, seed=1))
        self.assertIn("Admitted Updates      : 0 (0.00%)", report)
        with self.assertRaises(ValueError):
            run_monte_carlo(iterations=-1)
        with self.assertRaises(ValueError):
            run_monte_carlo(noise_scale=-1)

    def test_cli_main(self) -> None:
        from oes32_membrane_shield.__main__ import main

        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["oes32-simulate", "--iterations", "1", "--seed", "1"]),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(main(), 0)
        self.assertIn("Total Cycles Tested", output.getvalue())


if __name__ == "__main__":
    unittest.main()
