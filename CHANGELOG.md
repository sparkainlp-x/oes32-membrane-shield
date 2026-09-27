# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-27

### Changed (breaking)
- Removed `MembraneShield.issue_token()` / `verify_token()` (in-process HMAC tokens). The constructor now requires a `CapabilityVerifier`; callers pass externally issued, short-lived, payload-bound Ed25519 capabilities.
- Calibration requires signed approvals from distinct `CALIBRATEUR` and `GARDIEN` authorities (distinct keys and subjects).

### Added
- End-to-end and deterministic fuzz tests; CI with coverage gate (≥ 90 %), ruff, mypy, wheel build and pip-audit on Python 3.10 to 3.12.
- `CITATION.cff`, `.zenodo.json`, scope-and-evidence table, and a note on how the package relates to ADR-001 / oes32_engine.

### Documentation
- `SECURITY_AUDIT_REPORT.md` is marked as a historical assessment of v1; `SECURITY.md` is updated for the v2 model.

## [1.0.0] - 2026-08-27

### Added
- Initial reference implementation with process-local HMAC tokens (superseded).
