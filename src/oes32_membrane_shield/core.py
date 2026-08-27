"""OES-32 membrane shield state machine.

The shield admits boundary updates only when authentication, health checks,
residual limits, and the configured symmetry sector all pass.
"""

from __future__ import annotations

import hmac
import random
import secrets
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import isfinite
from statistics import mean, median
from typing import TypedDict

WIDTH = 32
MU_TABLE: tuple[int, ...] = tuple((i + 16) % WIDTH for i in range(WIDTH))
FOLD8_RINGS: tuple[tuple[int, ...], ...] = tuple(
    tuple((start + 4 * step) % WIDTH for step in range(8)) for start in range(4)
)


class Role(str, Enum):
    """Roles recognized by the shield's access-control boundary."""

    OBSERVATEUR = "observateur"
    CALIBRATEUR = "calibrateur"
    DECODEUR = "decodeur"
    GARDIEN = "gardien"


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
    """A non-sensitive record of an authorization or state-machine decision."""

    timestamp_ns: int
    role: str
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
    """Authenticated state machine implementing the OES-32 update contract."""

    def __init__(
        self,
        reference: OES32State | None = None,
        *,
        tau: float = 0.08,
        sector: Sector = Sector.ANY,
        epsilon: float = 1e-9,
        audit_size: int = 1024,
    ) -> None:
        if not isinstance(sector, Sector):
            raise ValueError("sector must be a Sector value")
        if not isfinite(float(tau)) or tau < 0:
            raise ValueError("tau must be finite and non-negative")
        if not isfinite(float(epsilon)) or epsilon < 0:
            raise ValueError("epsilon must be finite and non-negative")
        if not isinstance(audit_size, int) or isinstance(audit_size, bool) or audit_size < 1:
            raise ValueError("audit_size must be a positive integer")

        self.reference = reference or OES32State.zeros()
        self.state = self.reference
        self.tau = float(tau)
        self.sector = sector
        self.epsilon = float(epsilon)
        self.cycle = 0
        self.latched = False
        self._calibration_sealed = True
        self._secrets = {role: secrets.token_bytes(32) for role in Role}
        self._audit_log: list[AuditEvent | None] = [None] * audit_size
        self._audit_ptr = 0

    @property
    def audit_size(self) -> int:
        """Configured maximum number of retained audit events."""

        return len(self._audit_log)

    def audit_events(self) -> tuple[AuditEvent, ...]:
        """Return retained audit events in chronological order."""

        events = [event for event in self._audit_log if event is not None]
        if len(events) < self.audit_size or self._audit_ptr == 0:
            return tuple(events)
        return tuple(self._audit_log[self._audit_ptr :] + self._audit_log[: self._audit_ptr])  # type: ignore[arg-type]

    def reset(self) -> None:
        """Clear the latch and restore the current calibrated reference state."""

        self.state = self.reference
        self.latched = False

    def issue_token(self, role: Role) -> str:
        """Issue a process-local token for *role*.

        Tokens are intentionally not persisted or serialized. A new shield
        instance creates a new secret for every role.
        """

        if not isinstance(role, Role):
            raise ValueError("role must be a Role value")
        return hmac.new(self._secrets[role], role.value.encode(), sha256).hexdigest()

    def verify_token(self, role: Role, token: str) -> bool:
        """Constant-time verify a role token without exposing secret material."""

        if not isinstance(role, Role) or not isinstance(token, str):
            return False
        return hmac.compare_digest(self.issue_token(role), token)

    def _record_audit(self, role: Role, admitted: bool, reason: str, residual: float) -> None:
        self._audit_log[self._audit_ptr] = AuditEvent(
            time.perf_counter_ns(), role.value, admitted, reason, residual
        )
        self._audit_ptr = (self._audit_ptr + 1) % self.audit_size

    def observe(self, role: Role, token: str) -> OES32State:
        """Return the current state after authenticating an observer role."""

        if not self.verify_token(role, token):
            role_name = role.value if isinstance(role, Role) else "unknown"
            raise LoopDenied(f"Invalid HMAC token for role {role_name}")
        self._record_audit(role, True, "observe success", 0.0)
        return self.state

    def calibrate(self, cal_token: str, gar_token: str, new_reference: OES32State) -> None:
        """Replace the reference under dual control."""

        if not self.verify_token(Role.CALIBRATEUR, cal_token):
            raise LoopDenied("Invalid Calibrateur token")
        if not self.verify_token(Role.GARDIEN, gar_token):
            raise LoopDenied("Invalid Gardien token. Dual-control required.")
        if not isinstance(new_reference, OES32State):
            raise TypeError("new_reference must be an OES32State")
        self.reference = new_reference
        self.state = new_reference
        self.latched = False
        self._calibration_sealed = True
        self._record_audit(Role.CALIBRATEUR, True, "dual-control calibration updated", 0.0)

    def request_flip(
        self,
        role: Role,
        token: str,
        new_boundary: Iterable[float],
        *,
        syndrome_ok: bool = True,
        logical_ok: bool = True,
    ) -> LoopResult:
        """Evaluate and possibly admit a boundary update."""

        self.cycle += 1
        if not isinstance(role, Role):
            return LoopResult(self.cycle, False, "invalid role", float("inf"), self.state)
        if role not in (Role.DECODEUR, Role.GARDIEN):
            self._record_audit(role, False, f"role {role.value} denied write access", float("inf"))
            return LoopResult(
                self.cycle,
                False,
                f"role {role.value} denied write access",
                float("inf"),
                self.state,
            )
        if not self.verify_token(role, token):
            self._record_audit(role, False, "invalid write token", float("inf"))
            return LoopResult(self.cycle, False, "invalid write token", float("inf"), self.state)
        if self.latched:
            return LoopResult(self.cycle, False, "loop is latched", float("inf"), self.state)
        if not self._calibration_sealed:
            return LoopResult(self.cycle, False, "calibration unsealed", float("inf"), self.state)
        if not syndrome_ok:
            self._record_audit(role, False, "syndrome rejected", 0.0)
            return LoopResult(self.cycle, False, "syndrome rejected", 0.0, self.state)
        if not logical_ok:
            self._record_audit(role, False, "logical check rejected", 0.0)
            return LoopResult(self.cycle, False, "logical check rejected", 0.0, self.state)

        try:
            boundary = vector32(new_boundary, "new_boundary")
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
                self._record_audit(role, False, "residual breach; loop latched", residual)
                return LoopResult(
                    self.cycle, False, "residual breach; loop latched", residual, self.state
                )
            validator = SECTOR_VALIDATORS[self.sector]
            if not validator(
                tuple(x - y for x, y in zip(boundary, self.reference.boundary, strict=True)),
                self.epsilon,
            ):
                self._record_audit(role, False, "boundary symmetry rejected", residual)
                return LoopResult(
                    self.cycle, False, "boundary symmetry rejected", residual, self.state
                )
            if not validator(
                tuple(x - y for x, y in zip(new_bulk, self.reference.bulk, strict=True)),
                self.epsilon,
            ):
                self._record_audit(role, False, "bulk symmetry rejected", residual)
                return LoopResult(self.cycle, False, "bulk symmetry rejected", residual, self.state)
        except LoopDenied as exc:
            self._record_audit(role, False, str(exc), float("inf"))
            return LoopResult(self.cycle, False, str(exc), float("inf"), self.state)

        self.state = OES32State(new_bulk, boundary)
        self._record_audit(role, True, "admitted", residual)
        return LoopResult(self.cycle, True, "admitted", residual, self.state)


def run_monte_carlo(
    iterations: int = 5000,
    tau: float = 0.08,
    noise_scale: float = 0.02,
    *,
    seed: int | None = None,
) -> MonteCarloStats:
    """Run a lightweight simulation and return aggregate metrics.

    Passing ``seed`` makes proposal generation reproducible; timing values are
    still machine-dependent and should not be used as a benchmark.
    """

    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 0:
        raise ValueError("iterations must be a non-negative integer")
    if not isfinite(float(noise_scale)) or noise_scale < 0:
        raise ValueError("noise_scale must be finite and non-negative")

    rng = random.Random(seed)
    shield = MembraneShield(tau=tau, sector=Sector.ANY)
    token = shield.issue_token(Role.DECODEUR)
    stats: MonteCarloStats = {
        "total_cycles": iterations,
        "admitted": 0,
        "rejected_residual": 0,
        "rejected_symmetry": 0,
        "latched_count": 0,
        "latencies_ns": [],
    }
    latencies = stats["latencies_ns"]

    for _ in range(iterations):
        if shield.latched:
            shield.reset()
        proposal = [
            rng.uniform(-1.0, 1.0)
            if rng.random() < 0.05 and index == 0
            else rng.gauss(0.0, noise_scale)
            for index in range(WIDTH)
        ]
        started = time.perf_counter_ns()
        result = shield.request_flip(Role.DECODEUR, token, proposal)
        latencies.append(time.perf_counter_ns() - started)
        if result.admitted:
            stats["admitted"] = int(stats["admitted"]) + 1
        elif "residual breach" in result.reason:
            stats["rejected_residual"] = int(stats["rejected_residual"]) + 1
        elif "symmetry" in result.reason:
            stats["rejected_symmetry"] = int(stats["rejected_symmetry"]) + 1
        if shield.latched:
            stats["latched_count"] = int(stats["latched_count"]) + 1
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
