"""OES-32 membrane shield state machine with external authorization."""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from math import isfinite
from statistics import mean, median
from typing import TypedDict

from .authorization import (
    Action,
    AuthorizationError,
    CapabilityVerifier,
    Role,
    SignedCapability,
)

WIDTH = 32
MU_TABLE: tuple[int, ...] = tuple((i + 16) % WIDTH for i in range(WIDTH))
FOLD8_RINGS: tuple[tuple[int, ...], ...] = tuple(
    tuple((start + 4 * step) % WIDTH for step in range(8)) for start in range(4)
)


class Sector(str, Enum):
    """Symmetry constraint applied to accepted state deltas."""

    ANY = "ANY"
    EVEN = "EVEN"
    ODD = "ODD"
    FOLD8 = "FOLD8"


class LoopDenied(Exception):
    """Raised when an operation cannot be authorized or validated."""


def vector32(values: Iterable[float], name: str = "vector") -> tuple[float, ...]:
    """Coerce *values* to a finite vector with exactly 32 slots."""

    try:
        result = tuple(float(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise LoopDenied(f"{name} must contain real numbers") from exc
    if len(result) != WIDTH:
        raise LoopDenied(f"{name} must contain exactly {WIDTH} slots")
    if not all(isfinite(value) for value in result):
        raise LoopDenied(f"{name} contains NaN or infinity")
    return result


def fast_residual_max(a: Sequence[float], b: Sequence[float]) -> float:
    """Return the maximum absolute component-wise residual."""

    if len(a) != len(b):
        raise ValueError("residual vectors must have equal lengths")
    return max((abs(x - y) for x, y in zip(a, b, strict=True)), default=0.0)


def _check_even(delta: tuple[float, ...], epsilon: float) -> bool:
    return all(abs(delta[i] - delta[MU_TABLE[i]]) <= epsilon for i in range(WIDTH // 2))


def _check_odd(delta: tuple[float, ...], epsilon: float) -> bool:
    return all(abs(delta[i] + delta[MU_TABLE[i]]) <= epsilon for i in range(WIDTH // 2))


def _check_fold8(delta: tuple[float, ...], epsilon: float) -> bool:
    return all(
        abs(delta[ring[index]] - delta[ring[(index + 1) % 8]]) <= epsilon
        for ring in FOLD8_RINGS
        for index in range(8)
    )


SECTOR_VALIDATORS: Mapping[Sector, Callable[[tuple[float, ...], float], bool]] = {
    Sector.ANY: lambda *_: True,
    Sector.EVEN: _check_even,
    Sector.ODD: _check_odd,
    Sector.FOLD8: _check_fold8,
}


def _canonical_state(state: OES32State) -> bytes:
    return json.dumps(
        {"bulk": state.bulk, "boundary": state.boundary},
        separators=(",", ":"),
    ).encode("utf-8")


def calibration_payload(state: OES32State) -> bytes:
    """Return the exact bytes both calibration authorities must approve."""

    return _canonical_state(state)


def boundary_payload(boundary: Iterable[float]) -> bytes:
    """Return the exact bytes a write authority must approve."""

    return json.dumps(vector32(boundary, "boundary"), separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class OES32State:
    """Immutable 32-slot bulk and boundary state."""

    bulk: tuple[float, ...]
    boundary: tuple[float, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "bulk", vector32(self.bulk, "bulk"))
        object.__setattr__(self, "boundary", vector32(self.boundary, "boundary"))

    @classmethod
    def zeros(cls) -> OES32State:
        zero = (0.0,) * WIDTH
        return cls(zero, zero)

    @classmethod
    def create(cls, bulk: Iterable[float], boundary: Iterable[float]) -> OES32State:
        return cls(vector32(bulk, "bulk"), vector32(boundary, "boundary"))


@dataclass(frozen=True)
class LoopResult:
    """Outcome of a proposed boundary update."""

    cycle: int
    admitted: bool
    reason: str
    residual: float
    state: OES32State


@dataclass(frozen=True)
class AuditEvent:
    """Non-sensitive metadata for an authorization or state-machine decision."""

    timestamp_ns: int
    role: str
    subject: str
    request_id: str
    admitted: bool
    reason: str
    residual: float


class MonteCarloStats(TypedDict):
    """Aggregate metrics returned by :func:`run_monte_carlo`."""

    total_cycles: int
    admitted: int
    rejected_residual: int
    rejected_symmetry: int
    latched_count: int
    latencies_ns: list[int]


class MembraneShield:
    """State machine whose credentials are issued and held outside the object.

    The verifier contains public keys only. Callers must obtain capabilities
    from independent authority processes and pass them into this object.
    """

    def __init__(
        self,
        verifier: CapabilityVerifier,
        reference: OES32State | None = None,
        *,
        tau: float = 0.08,
        sector: Sector = Sector.ANY,
        epsilon: float = 1e-9,
        audit_size: int = 1024,
    ) -> None:
        if not isinstance(verifier, CapabilityVerifier):
            raise ValueError("verifier must be a CapabilityVerifier")
        if not isinstance(sector, Sector):
            raise ValueError("sector must be a Sector value")
        if not isfinite(float(tau)) or tau < 0:
            raise ValueError("tau must be finite and non-negative")
        if not isfinite(float(epsilon)) or epsilon < 0:
            raise ValueError("epsilon must be finite and non-negative")
        if not isinstance(audit_size, int) or isinstance(audit_size, bool) or audit_size < 1:
            raise ValueError("audit_size must be a positive integer")

        self._verifier = verifier
        self.reference = reference or OES32State.zeros()
        self.state = self.reference
        self.tau = float(tau)
        self.sector = sector
        self.epsilon = float(epsilon)
        self.cycle = 0
        self.latched = False
        self._audit_log: list[AuditEvent | None] = [None] * audit_size
        self._audit_ptr = 0

    @property
    def audit_size(self) -> int:
        return len(self._audit_log)

    def audit_events(self) -> tuple[AuditEvent, ...]:
        events = [event for event in self._audit_log if event is not None]
        if len(events) < self.audit_size or self._audit_ptr == 0:
            return tuple(events)
        return tuple(self._audit_log[self._audit_ptr :] + self._audit_log[: self._audit_ptr])  # type: ignore[arg-type]

    def _record_audit(
        self,
        capability: SignedCapability,
        admitted: bool,
        reason: str,
        residual: float,
    ) -> None:
        self._audit_log[self._audit_ptr] = AuditEvent(
            time.perf_counter_ns(),
            capability.role.value,
            capability.subject,
            capability.request_id,
            admitted,
            reason,
            residual,
        )
        self._audit_ptr = (self._audit_ptr + 1) % self.audit_size

    def reset(self, authorization: SignedCapability) -> None:
        """Reset the latch only with a guardian write capability."""

        try:
            verified = self._verifier.verify(
                authorization, action=Action.WRITE, role=Role.GARDIEN, payload=b"reset"
            )
        except AuthorizationError as exc:
            raise LoopDenied(str(exc)) from exc
        self.state = self.reference
        self.latched = False
        self._record_audit(verified, True, "reset", 0.0)

    def observe(self, authorization: SignedCapability) -> OES32State:
        """Return the current state after verifying an observer capability."""

        try:
            verified = self._verifier.verify(
                authorization, action=Action.OBSERVE, role=Role.OBSERVATEUR
            )
        except AuthorizationError as exc:
            raise LoopDenied(str(exc)) from exc
        self._record_audit(verified, True, "observe success", 0.0)
        return self.state

    def calibrate(
        self,
        calibrator_approval: SignedCapability,
        guardian_approval: SignedCapability,
        new_reference: OES32State,
    ) -> None:
        """Replace the reference using independent calibrator and guardian approvals."""

        if not isinstance(new_reference, OES32State):
            raise TypeError("new_reference must be an OES32State")
        if not isinstance(calibrator_approval, SignedCapability) or not isinstance(
            guardian_approval, SignedCapability
        ):
            raise LoopDenied("calibration approvals have invalid type")
        if {calibrator_approval.role, guardian_approval.role} != {
            Role.CALIBRATEUR,
            Role.GARDIEN,
        }:
            raise LoopDenied("calibration requires Calibrateur and Gardien approvals")
        try:
            approvals = self._verifier.verify_independent_pair(
                calibrator_approval,
                guardian_approval,
                action=Action.CALIBRATE,
                payload=calibration_payload(new_reference),
            )
        except AuthorizationError as exc:
            raise LoopDenied(str(exc)) from exc
        if {approval.role for approval in approvals} != {Role.CALIBRATEUR, Role.GARDIEN}:
            raise LoopDenied("calibration requires Calibrateur and Gardien approvals")
        self.reference = new_reference
        self.state = new_reference
        self.latched = False
        self._record_audit(approvals[0], True, "dual-control calibration updated", 0.0)
        self._record_audit(approvals[1], True, "dual-control calibration updated", 0.0)

    def request_flip(
        self,
        authorization: SignedCapability,
        new_boundary: Iterable[float],
        *,
        syndrome_ok: bool = True,
        logical_ok: bool = True,
    ) -> LoopResult:
        """Verify a scoped write capability, then evaluate and possibly commit a proposal."""

        self.cycle += 1
        try:
            boundary = vector32(new_boundary, "new_boundary")
            verified = self._verifier.verify(
                authorization,
                action=Action.WRITE,
                role=authorization.role,
                payload=boundary_payload(boundary),
            )
        except (AuthorizationError, LoopDenied, AttributeError) as exc:
            return LoopResult(self.cycle, False, str(exc), float("inf"), self.state)
        if verified.role not in (Role.DECODEUR, Role.GARDIEN):
            self._record_audit(
                verified, False, f"role {verified.role.value} denied write access", float("inf")
            )
            return LoopResult(
                self.cycle,
                False,
                f"role {verified.role.value} denied write access",
                float("inf"),
                self.state,
            )
        if self.latched:
            self._record_audit(verified, False, "loop is latched", float("inf"))
            return LoopResult(self.cycle, False, "loop is latched", float("inf"), self.state)
        if not syndrome_ok:
            self._record_audit(verified, False, "syndrome rejected", 0.0)
            return LoopResult(self.cycle, False, "syndrome rejected", 0.0, self.state)
        if not logical_ok:
            self._record_audit(verified, False, "logical check rejected", 0.0)
            return LoopResult(self.cycle, False, "logical check rejected", 0.0, self.state)

        delta_boundary = tuple(
            new_value - old_value
            for new_value, old_value in zip(boundary, self.state.boundary, strict=True)
        )
        new_bulk = tuple(
            old_value + delta
            for old_value, delta in zip(self.state.bulk, delta_boundary, strict=True)
        )
        residual = max(
            fast_residual_max(boundary, self.reference.boundary),
            fast_residual_max(new_bulk, self.reference.bulk),
        )
        if residual > self.tau:
            self.latched = True
            self._record_audit(verified, False, "residual breach; loop latched", residual)
            return LoopResult(
                self.cycle, False, "residual breach; loop latched", residual, self.state
            )
        validator = SECTOR_VALIDATORS[self.sector]
        if not validator(
            tuple(x - y for x, y in zip(boundary, self.reference.boundary, strict=True)),
            self.epsilon,
        ):
            self._record_audit(verified, False, "boundary symmetry rejected", residual)
            return LoopResult(self.cycle, False, "boundary symmetry rejected", residual, self.state)
        if not validator(
            tuple(x - y for x, y in zip(new_bulk, self.reference.bulk, strict=True)), self.epsilon
        ):
            self._record_audit(verified, False, "bulk symmetry rejected", residual)
            return LoopResult(self.cycle, False, "bulk symmetry rejected", residual, self.state)

        self.state = OES32State(new_bulk, boundary)
        self._record_audit(verified, True, "admitted", residual)
        return LoopResult(self.cycle, True, "admitted", residual, self.state)


def run_monte_carlo(
    iterations: int = 5000,
    tau: float = 0.08,
    noise_scale: float = 0.02,
    *,
    seed: int | None = None,
) -> MonteCarloStats:
    """Run a simulation using a locally generated decoder authority."""

    from .authorization import CapabilityIssuer

    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 0:
        raise ValueError("iterations must be a non-negative integer")
    if not isfinite(float(noise_scale)) or noise_scale < 0:
        raise ValueError("noise_scale must be finite and non-negative")
    issuer = CapabilityIssuer.generate("simulation-decoder", "simulation", Role.DECODEUR)
    guardian = CapabilityIssuer.generate("simulation-guardian", "simulation-guardian", Role.GARDIEN)
    verifier = CapabilityVerifier(
        {issuer.key_id: issuer.authority_key(), guardian.key_id: guardian.authority_key()}
    )
    shield = MembraneShield(verifier, tau=tau, sector=Sector.ANY)
    rng = random.Random(seed)
    stats: MonteCarloStats = {
        "total_cycles": iterations,
        "admitted": 0,
        "rejected_residual": 0,
        "rejected_symmetry": 0,
        "latched_count": 0,
        "latencies_ns": [],
    }
    for _ in range(iterations):
        if shield.latched:
            reset = guardian.issue(Action.WRITE, b"reset")
            shield.reset(reset)
        proposal = [
            rng.uniform(-1.0, 1.0)
            if rng.random() < 0.05 and index == 0
            else rng.gauss(0.0, noise_scale)
            for index in range(WIDTH)
        ]
        authorization = issuer.issue(Action.WRITE, boundary_payload(proposal))
        started = time.perf_counter_ns()
        result = shield.request_flip(authorization, proposal)
        stats["latencies_ns"].append(time.perf_counter_ns() - started)
        if result.admitted:
            stats["admitted"] += 1
        elif "residual breach" in result.reason:
            stats["rejected_residual"] += 1
        elif "symmetry" in result.reason:
            stats["rejected_symmetry"] += 1
        if shield.latched:
            stats["latched_count"] += 1
    return stats


def format_monte_carlo_report(results: MonteCarloStats) -> str:
    """Format simulation results for a human-readable command-line report."""

    total = results["total_cycles"]
    latencies_us = [value / 1000.0 for value in results["latencies_ns"]]
    admitted = results["admitted"]
    lines = [
        f"Total Cycles Tested   : {total}",
        f"Admitted Updates      : {admitted} ({admitted / total * 100:.2f}%)"
        if total
        else "Admitted Updates      : 0 (0.00%)",
        f"Residual Breaches     : {results['rejected_residual']}",
        f"Circuit Breaker Trips : {results['latched_count']}",
    ]
    if latencies_us:
        lines.extend(
            [
                f"Execution Latency p50 : {median(latencies_us):.2f} µs",
                f"Execution Latency mean: {mean(latencies_us):.2f} µs",
            ]
        )
    return "\n".join(lines)
