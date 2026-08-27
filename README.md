# OES-32 Membrane Shield

A small, dependency-free Python library for evaluating authenticated updates to a 32-slot state vector. The shield combines role-scoped HMAC tokens, dual-control calibration, residual-based circuit breaking, configurable symmetry sectors, and a bounded audit ring.

> This project is a reference implementation of a state-machine contract. It is not a substitute for a production security review, a hardware safety case, or a cryptographic key-management system.

## What it does

`MembraneShield` starts from an immutable bulk/boundary reference state. A decoder or guardian may propose a new boundary vector. The shield derives the corresponding bulk delta, checks the residual against `tau`, applies the configured sector validator, and commits the update only if every gate passes. A residual breach latches the loop until an explicit reset.

| Control | Behavior |
| --- | --- |
| Role authentication | Tokens are role-specific, process-local HMAC values and are compared in constant time. |
| Write access | Only `DECODEUR` and `GARDIEN` may request updates. |
| Calibration | A new reference requires both `CALIBRATEUR` and `GARDIEN` tokens. |
| Residual limit | Any residual above `tau` is rejected and latches the shield. |
| Symmetry sector | `ANY`, `EVEN`, `ODD`, and `FOLD8` validators are available. |
| Audit | A bounded ring retains non-sensitive decisions in chronological order. |

## Installation

The package requires Python 3.10 or newer and has no runtime dependencies.

```bash
python -m pip install .
```

For an editable development installation with common tooling:

```bash
python -m pip install -e .
python -m pip install pytest ruff mypy
```

## Quick start

```python
from oes32_membrane_shield import MembraneShield, Role, Sector

shield = MembraneShield(tau=0.5, sector=Sector.ANY)
token = shield.issue_token(Role.DECODEUR)
proposal = [0.1] + [0.0] * 31

result = shield.request_flip(Role.DECODEUR, token, proposal)
print(result.admitted, result.reason)
print(shield.audit_events())
```

For a deterministic simulation:

```bash
python -m oes32_membrane_shield --iterations 5000 --seed 7
```

The installed console command `oes32-simulate` provides the same interface.

## API notes

`OES32State.create(bulk, boundary)` validates that both inputs contain exactly 32 finite real values. `request_flip` returns a `LoopResult` rather than raising for normal proposal rejection, making rejected updates explicit and easy to instrument. Malformed vectors are represented as rejected results with the state left unchanged.

`audit_events()` exposes decision metadata but never stores or returns caller tokens. The audit ring is bounded by `audit_size`; use an external append-only sink when retention, compliance, or cross-process forensics are required.

The simulation helper accepts an optional `seed` so proposal counts can be reproduced. Latency measurements are machine-dependent and are intended for diagnostics, not benchmarking.

## Development

Run the full test suite with:

```bash
python -m unittest discover -s tests -v
pytest
ruff check .
mypy src
```

The project uses a `src/` layout, type annotations, immutable state records, and a minimal standard-library runtime surface. GitHub Actions runs the test matrix on supported Python versions and checks code quality.

## Security considerations

The HMAC secrets are generated in memory for each `MembraneShield` instance. They are not persisted, rotated, distributed, or integrated with an operating-system secret store. Applications handling real credentials should provide a dedicated key-management design and should not treat these process-local tokens as identity proof across services.

The implementation is intentionally deterministic in its state transitions, but it does not claim timing-channel resistance for the entire application. Only token comparison uses constant-time comparison. Review deployment, logging, memory handling, and authorization policy before relying on this code in a sensitive environment.

## License

Released under the MIT License. See [LICENSE](LICENSE).
