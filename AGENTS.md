# Agent Guidelines

When working on this scanner, keep these production and auditability principles front and center:

- Production probes must be non-mutating by default. Any probe that can create, update, delete, register, publish, or otherwise alter a target system must require an explicit opt-in and must make that opt-in visible in the report.
- Distinguish unknown, unauthorized, unreachable, and truly empty evidence. A 401/403 response, failed API call, or missing permission is not proof that a resource list is empty.
- Emit auditable per-control evidence. Every control result should explain what was evaluated, which collectors supplied the data, what status was reached, and which observed values support that status, with secrets redacted.
- Managed-service coverage must be verified. Do not let a manual flavor override or hostname guess silently satisfy a control unless a trusted collector produced enough vendor-specific evidence to justify the coverage claim.
- Support real Kafka client configuration. Production clusters commonly require truststores, keystores, mTLS, OAuth, callback handlers, and custom client properties; the scanner should accept those properties rather than relying only on simplified CLI flags.
- Tests must cover these failure modes directly. Add regressions for non-mutating defaults, unauthorized-versus-empty evidence, per-control evidence emission, managed-service coverage verification, and production client configuration loading.
