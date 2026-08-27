from __future__ import annotations

import contextlib
import io
import math
import sys
import unittest
from unittest.mock import patch

from oes32_membrane_shield import (
    WIDTH,
    LoopDenied,
    MembraneShield,
    OES32State,
    Role,
    Sector,
    fast_residual_max,
    format_monte_carlo_report,
    run_monte_carlo,
)


class MembraneShieldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.shield = MembraneShield(tau=0.5)
        self.observer_token = self.shield.issue_token(Role.OBSERVATEUR)
        self.decoder_token = self.shield.issue_token(Role.DECODEUR)
        self.calibrator_token = self.shield.issue_token(Role.CALIBRATEUR)
        self.guardian_token = self.shield.issue_token(Role.GARDIEN)

    def test_zero_state_and_observation(self) -> None:
        state = self.shield.observe(Role.OBSERVATEUR, self.observer_token)
        self.assertEqual(len(state.boundary), WIDTH)
        self.assertEqual(state, OES32State.zeros())

    def test_observer_cannot_write(self) -> None:
        result = self.shield.request_flip(Role.OBSERVATEUR, self.observer_token, [0.0] * WIDTH)
        self.assertFalse(result.admitted)
        self.assertIn("denied write access", result.reason)

    def test_invalid_token_is_rejected(self) -> None:
        result = self.shield.request_flip(Role.DECODEUR, "bad", [0.0] * WIDTH)
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason, "invalid write token")

    def test_valid_flip_updates_bulk_and_boundary(self) -> None:
        boundary = [0.1 if index == 0 else 0.0 for index in range(WIDTH)]
        result = self.shield.request_flip(Role.DECODEUR, self.decoder_token, boundary)
        self.assertTrue(result.admitted)
        self.assertEqual(result.state.boundary[0], 0.1)
        self.assertEqual(result.state.bulk[0], 0.1)

    def test_residual_breach_latches_and_preserves_state(self) -> None:
        result = self.shield.request_flip(
            Role.DECODEUR,
            self.decoder_token,
            [1.5 if index == 0 else 0.0 for index in range(WIDTH)],
        )
        self.assertFalse(result.admitted)
        self.assertTrue(self.shield.latched)
        self.assertEqual(self.shield.state, OES32State.zeros())
        follow_up = self.shield.request_flip(Role.DECODEUR, self.decoder_token, [0.0] * WIDTH)
        self.assertEqual(follow_up.reason, "loop is latched")

    def test_reset_clears_latch(self) -> None:
        self.shield.request_flip(Role.DECODEUR, self.decoder_token, [1.5] + [0.0] * (WIDTH - 1))
        self.shield.reset()
        self.assertFalse(self.shield.latched)

    def test_health_checks_are_enforced(self) -> None:
        proposal = [0.1] + [0.0] * (WIDTH - 1)
        self.assertEqual(
            self.shield.request_flip(
                Role.DECODEUR, self.decoder_token, proposal, syndrome_ok=False
            ).reason,
            "syndrome rejected",
        )
        self.assertEqual(
            self.shield.request_flip(
                Role.DECODEUR, self.decoder_token, proposal, logical_ok=False
            ).reason,
            "logical check rejected",
        )

    def test_bad_vectors_are_rejected_without_mutation(self) -> None:
        for proposal in ([0.0] * 16, ["x"] * WIDTH):
            result = self.shield.request_flip(Role.DECODEUR, self.decoder_token, proposal)
            self.assertFalse(result.admitted)
            self.assertEqual(self.shield.state, OES32State.zeros())

    def test_even_and_odd_symmetry(self) -> None:
        even = MembraneShield(tau=0.5, sector=Sector.EVEN)
        even_boundary = [0.0] * WIDTH
        even_boundary[0] = even_boundary[16] = 0.2
        self.assertTrue(
            even.request_flip(
                Role.DECODEUR, even.issue_token(Role.DECODEUR), even_boundary
            ).admitted
        )

        odd = MembraneShield(tau=0.5, sector=Sector.ODD)
        odd_boundary = [0.0] * WIDTH
        odd_boundary[0], odd_boundary[16] = 0.2, -0.2
        self.assertTrue(
            odd.request_flip(Role.DECODEUR, odd.issue_token(Role.DECODEUR), odd_boundary).admitted
        )

    def test_fold8_symmetry_accepts_constant_rings(self) -> None:
        shield = MembraneShield(tau=0.5, sector=Sector.FOLD8)
        boundary = [0.2] * WIDTH
        result = shield.request_flip(Role.DECODEUR, shield.issue_token(Role.DECODEUR), boundary)
        self.assertTrue(result.admitted)

    def test_invalid_role_is_rejected(self) -> None:
        result = self.shield.request_flip("decodeur", "bad", [0.0] * WIDTH)  # type: ignore[arg-type]
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason, "invalid role")

    def test_symmetry_failure_is_rejected(self) -> None:
        shield = MembraneShield(tau=0.5, sector=Sector.EVEN)
        boundary = [0.0] * WIDTH
        boundary[0] = 0.2
        result = shield.request_flip(Role.DECODEUR, shield.issue_token(Role.DECODEUR), boundary)
        self.assertEqual(result.reason, "boundary symmetry rejected")

    def test_dual_control_calibration(self) -> None:
        reference = OES32State.create([0.1] * WIDTH, [0.1] * WIDTH)
        self.shield.calibrate(self.calibrator_token, self.guardian_token, reference)
        self.assertEqual(self.shield.state, reference)
        with self.assertRaises(LoopDenied):
            self.shield.calibrate(self.observer_token, self.guardian_token, reference)
        with self.assertRaises(LoopDenied):
            self.shield.calibrate(self.calibrator_token, self.observer_token, reference)

    def test_audit_events_are_public_but_non_sensitive(self) -> None:
        self.shield.observe(Role.OBSERVATEUR, self.observer_token)
        self.shield.request_flip(Role.DECODEUR, self.decoder_token, [0.0] * WIDTH)
        events = self.shield.audit_events()
        self.assertEqual(len(events), 2)
        self.assertNotIn(self.decoder_token, repr(events))
        self.assertEqual(events[-1].reason, "admitted")

    def test_audit_ring_retains_latest_events(self) -> None:
        shield = MembraneShield(audit_size=2)
        token = shield.issue_token(Role.DECODEUR)
        for _ in range(3):
            shield.request_flip(Role.DECODEUR, token, [0.0] * WIDTH)
        self.assertEqual(len(shield.audit_events()), 2)
        self.assertEqual(
            [event.reason for event in shield.audit_events()], ["admitted", "admitted"]
        )

    def test_constructor_validation(self) -> None:
        with self.assertRaises(ValueError):
            MembraneShield(tau=-1)
        with self.assertRaises(ValueError):
            MembraneShield(epsilon=-1)
        with self.assertRaises(ValueError):
            MembraneShield(audit_size=0)
        with self.assertRaises(ValueError):
            MembraneShield(sector="EVEN")  # type: ignore[arg-type]

    def test_input_and_token_validation(self) -> None:
        with self.assertRaises(LoopDenied):
            OES32State.create([math.nan] * WIDTH, [0.0] * WIDTH)
        with self.assertRaises(ValueError):
            self.shield.issue_token("decodeur")  # type: ignore[arg-type]
        self.assertFalse(self.shield.verify_token("decodeur", self.decoder_token))  # type: ignore[arg-type]
        with self.assertRaises(LoopDenied):
            self.shield.observe("decodeur", self.decoder_token)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            fast_residual_max((1.0,), ())

    def test_calibration_requires_state_object(self) -> None:
        with self.assertRaises(TypeError):
            self.shield.calibrate(self.calibrator_token, self.guardian_token, object())  # type: ignore[arg-type]

    def test_wrapped_audit_order(self) -> None:
        shield = MembraneShield(audit_size=2)
        token = shield.issue_token(Role.DECODEUR)
        shield.request_flip(Role.DECODEUR, token, [0.0] * WIDTH)
        shield.request_flip(Role.DECODEUR, token, [0.0] * WIDTH)
        shield.request_flip(Role.DECODEUR, token, [0.0] * WIDTH)
        self.assertEqual(len(shield.audit_events()), 2)


class SimulationTests(unittest.TestCase):
    def test_seed_makes_counts_reproducible(self) -> None:
        first = run_monte_carlo(iterations=100, seed=7)
        second = run_monte_carlo(iterations=100, seed=7)
        for key in (
            "total_cycles",
            "admitted",
            "rejected_residual",
            "rejected_symmetry",
            "latched_count",
        ):
            self.assertEqual(first[key], second[key])

    def test_zero_iteration_report(self) -> None:
        report = format_monte_carlo_report(run_monte_carlo(iterations=0, seed=1))
        self.assertIn("Admitted Updates      : 0 (0.00%)", report)

    def test_simulation_validation_and_report(self) -> None:
        with self.assertRaises(ValueError):
            run_monte_carlo(iterations=-1)
        with self.assertRaises(ValueError):
            run_monte_carlo(noise_scale=-1)
        report = format_monte_carlo_report(run_monte_carlo(iterations=2, seed=3))
        self.assertIn("Execution Latency p50", report)

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
