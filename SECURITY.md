# Security Policy

## Scope

This repository is a reference implementation of an authenticated 32-slot state machine. It is **not certified safety-critical software**, a complete identity system, a key-management service, or a replacement for an application threat model and independent security review.

## Supported versions

| Version | Support |
| --- | --- |
| `2.x` | Security fixes and corrective maintenance while the project is actively maintained. |
| `1.x` (HMAC tokens) | Unsupported. Upgrade to 2.x. |
| Older versions | No guaranteed security support. Upgrade before reporting a suspected issue. |

## Reporting a vulnerability

Please do not open a public issue for an undisclosed vulnerability. Use GitHub's private vulnerability reporting feature if it is enabled for this repository, or contact the maintainer privately through the account's authenticated GitHub contact channel. Include a clear description, affected version or commit, reproducible steps, impact assessment, and a proposed mitigation if available. Do not include real credentials, private keys, personal data, or production secrets.

We will acknowledge a report when practicable, investigate the impact, and coordinate disclosure after a fix or mitigation is available. This project does not promise a specific response-time or disclosure deadline.

## Security design limitations

Version 2 verifies externally issued Ed25519 capabilities; the shield holds public keys only. Capabilities are scoped to an action and exact payload, expire, and are single-use **within one verifier instance**: replay state is in memory and is lost on restart. Deployments requiring real authorization still need protected private-key storage in separate trust domains, key rotation and revocation, durable replay state, authenticated transport, and an external identity policy. The historical [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) covers the superseded v1 HMAC design only.

The audit ring is bounded and local to one process. It is not tamper-evident, durable, centralized, or a compliance record. Applications requiring forensic evidence should forward sanitized events to an append-only, access-controlled logging system.

The residual and symmetry checks protect the state-machine contract only. They do not establish correctness of the surrounding physical model, input provenance, numerical stability under every workload, or system-level safety.
