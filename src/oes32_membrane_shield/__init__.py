"""Public API for the OES-32 membrane shield."""

from .core import (
    FOLD8_RINGS,
    MU_TABLE,
    WIDTH,
    AuditEvent,
    LoopDenied,
    LoopResult,
    MembraneShield,
    MonteCarloStats,
    OES32State,
    Role,
    Sector,
    fast_residual_max,
    format_monte_carlo_report,
    run_monte_carlo,
    vector32,
)

__all__ = [
    "AuditEvent",
    "FOLD8_RINGS",
    "LoopDenied",
    "LoopResult",
    "MU_TABLE",
    "MembraneShield",
    "MonteCarloStats",
    "OES32State",
    "Role",
    "Sector",
    "WIDTH",
    "fast_residual_max",
    "format_monte_carlo_report",
    "run_monte_carlo",
    "vector32",
]

__version__ = "1.0.0"
