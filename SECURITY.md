# Security Policy

## Scope

This repository is a reference implementation of an authenticated 32-slot state machine. It is **not certified safety-critical software**, a complete identity system, a key-management service, or a replacement for an application threat model and independent security review.

## Supported versions

| Version | Support |
| --- | --- |
| `1.x` | Security fixes and corrective maintenance while the project is actively maintained. |
| Older versions | No guaranteed security support. Upgrade before reporting a suspected issue. |

## Reporting a vulnerability

Please do not open a public issue for an undisclosed vulnerability. Use GitHub's private vulnerability reporting feature if it is enabled for this repository, or contact the maintainer privately through the account's authenticated GitHub contact channel. Include a clear description, affected version or commit, reproducible steps, impact assessment, and a proposed mitigation if available. Do not include real credentials, private keys, personal data, or production secrets.

We will acknowledge a report when practicable, investigate the impact, and coordinate disclosure after a fix or mitigation is available. This project does not promise a specific response-time or disclosure deadline.

## Security design limitations

The current library generates HMAC secrets in process memory. Tokens are process-local, do not expire, are not revocable independently, and are not suitable as service-to-service identity. Deployments requiring real authorization should integrate an external identity provider, a dedicated secret-management system, token rotation, expiration, revocation, replay policy, and authenticated transport.

The audit ring is bounded and local to one process. It is not tamper-evident, durable, centralized, or a compliance record. Applications requiring forensic evidence should forward sanitized events to an append-only, access-controlled logging system.

The residual and symmetry checks protect the state-machine contract only. They do not establish correctness of the surrounding physical model, input provenance, numerical stability under every workload, or system-level safety.
