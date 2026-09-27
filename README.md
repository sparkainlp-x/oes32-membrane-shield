# OES-32 Membrane Shield

[![CI](https://github.com/sparkainlp-x/oes32-membrane-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/sparkainlp-x/oes32-membrane-shield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: research prototype](https://img.shields.io/badge/status-research%20prototype-orange.svg)](#scope-and-evidence)

A Python library for evaluating externally authorized updates to a 32-slot state vector. The shield verifies short-lived Ed25519 capabilities issued outside the enforcement object, requires independent dual approval for calibration, applies residual-based circuit breaking and configurable symmetry sectors, and retains a bounded diagnostic audit ring.

> This project is a reference implementation of a state-machine contract. It is not a substitute for a production security review, a hardware safety case, or a cryptographic key-management system.

## What it does

`MembraneShield` starts from an immutable bulk/boundary reference state. A decoder or guardian may propose a new boundary vector. The shield derives the corresponding bulk delta, checks the residual against `tau`, applies the configured sector validator, and commits the update only if every gate passes. A residual breach latches the loop until an explicit reset.

| Control | Behavior |
| --- | --- |
| Role authentication | Short-lived, payload-bound Ed25519 capabilities are verified against public keys; private keys never enter the shield. |
| Write access | Only capabilities issued for `DECODEUR` or `GARDIEN` can authorize updates. |
| Calibration | A new reference requires approvals from distinct `CALIBRATEUR` and `GARDIEN` authorities, with distinct keys and subjects. |
| Residual limit | Any residual above `tau` is rejected and latches the shield. |
| Symmetry sector | `ANY`, `EVEN`, `ODD`, and `FOLD8` validators are available. |
| Audit | A bounded ring retains non-sensitive decisions in chronological order. |

## Version 2 authorization model

Version 2 removes `MembraneShield.issue_token()` and `verify_token()`. The shield constructor now requires a `CapabilityVerifier`, and callers pass signed capabilities into `observe`, `request_flip`, and `reset`. Calibration requires one signed approval from a `CALIBRATEUR` authority and one from a distinct `GARDIEN` authority. The shield stores public keys only; private signing keys must remain with their respective authority services.

This is a breaking change from version 1. Do not mechanically convert the old HMAC strings into capabilities. Create separate Ed25519 authorities, distribute only their public keys to the shield, and bind every capability to the exact action and payload.

## Installation

The package requires Python 3.10 or newer and depends on `cryptography` for Ed25519 signatures.

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
from oes32_membrane_shield import (
    Action,
    CapabilityIssuer,
    CapabilityVerifier,
    MembraneShield,
    Role,
    Sector,
    boundary_payload,
)

# The issuer owns the private key; the shield receives public verification data only.
decoder = CapabilityIssuer.generate("decoder-key", "decoder-service", Role.DECODEUR)
verifier = CapabilityVerifier({decoder.key_id: decoder.authority_key()})
shield = MembraneShield(verifier, tau=0.5, sector=Sector.ANY)
proposal = [0.1] + [0.0] * 31
authorization = decoder.issue(Action.WRITE, boundary_payload(proposal))

result = shield.request_flip(authorization, proposal)
print(result.admitted, result.reason)
print(shield.audit_events())
```

For a deterministic simulation:

```bash
python -m oes32_membrane_shield --iterations 5000 --seed 7
```

The installed console command `oes32-simulate` provides the same interface.

## API notes

`OES32State.create(bulk, boundary)` validates that both inputs contain exactly 32 finite real values. `CapabilityIssuer` signs scoped, expiring capabilities, while `CapabilityVerifier` checks the signature, role, action, payload digest, time window, and one-time request ID. `request_flip` returns a `LoopResult` rather than raising for normal proposal rejection, making rejected updates explicit and easy to instrument. Malformed vectors are represented as rejected results with the state left unchanged.

`audit_events()` exposes decision metadata, including the authority subject and request ID, but never stores or returns private keys or signatures. The audit ring is bounded by `audit_size`; use an external append-only sink when retention, compliance, or cross-process forensics are required.

The simulation helper accepts an optional `seed` so proposal counts can be reproduced. Latency measurements are machine-dependent and are intended for diagnostics, not benchmarking. The simulator creates separate decoder and guardian authorities to exercise the v2 model.

## Development

Run the full test suite with:

```bash
python -m unittest discover -s tests -v
pytest
ruff check .
mypy src
```

The project uses a `src/` layout, type annotations, immutable state records, external public-key authorization, and a small cryptography runtime surface. GitHub Actions runs the test matrix on supported Python versions, enforces at least 90% test coverage, checks code quality and strict types, builds a wheel, and audits the dependency environment. Dependabot monitors Python and Actions updates. Version tags matching `v*.*.*` trigger a release build with SHA-256 checksums.

Repository governance is documented in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Issue forms, CODEOWNERS, Dependabot configuration, and automatic branch cleanup are enabled. `main` is protected: changes arrive through pull requests with required CI checks and linear history, and force pushes are blocked.

## Security considerations

The shield no longer creates or stores private credentials. Authority processes create Ed25519 keypairs and issue capabilities; the shield receives public verification keys only. Capabilities are scoped to an action and exact payload, expire, and are single-use within a verifier instance. Production deployments still need protected private-key storage, key rotation and revocation, authenticated transport, durable replay state, and an external identity policy.

Calibration approvals are cryptographically independent only when operators actually use distinct authority keys and subjects. The library rejects same-role, same-key, or same-subject pairs, but deployment must protect each private key in a separate trust domain. The Python object remains mutable and should be isolated from untrusted in-process code; use a service/process boundary for hostile callers.

The implementation is intentionally deterministic in its state transitions, but it does not claim timing-channel resistance for the entire application. Review deployment, logging, memory handling, and authorization policy before relying on this code in a sensitive environment.

## Scope and evidence

| Item | Status |
| --- | --- |
| State-machine behaviour (residual latch, sectors, dual approval, capability checks) | Unit, end-to-end and deterministic fuzz tests; **SYNTHETIC** inputs |
| Simulation output (`oes32-simulate`) | **SYNTHETIC**; latency figures are machine-dependent diagnostics, not benchmarks |
| Independent security review of v2 | **UNRUN** (the [historical audit](SECURITY_AUDIT_REPORT.md) covers v1 only) |
| Hardware, field, medical or safety-certified use | **Not claimed** |

## Relationship to the OES-32 family

The residual is the maximum absolute component difference, and a residual strictly greater than `tau` is rejected and latches. This matches the normative definition in [oes32-residual](https://github.com/sparkainlp-x/oes32-residual) (ADR-001). The default `tau = 0.08` and the `EVEN` / `ODD` / `FOLD8` sectors correspond to the Profile A sidecar documented in [oes32_engine](https://github.com/sparkainlp-x/oes32_engine). This repository adds the authorization layer (Ed25519 capabilities, dual-approval calibration, audit ring) around that contract.

## Citation

See [CITATION.cff](CITATION.cff). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Released under the MIT License. See [LICENSE](LICENSE). Author: Jean-François Brisson / Spark AI NLP, https://sparkainlpx.xyz
