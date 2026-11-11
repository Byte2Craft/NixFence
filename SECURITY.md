# Security policy

**Current status: unauthenticated, read-only demonstration. Not for production.**

## Reporting

Please do not file exploitable vulnerabilities in public issues. Use GitHub private vulnerability reporting if configured by the repository owner. Before launch, Byte2craft must publish a maintained private contact channel and incident response policy; **no verified security email is configured in this starter kit**.

## Current trust boundary

- The demo binds to loopback in `compose.yaml` and does not authenticate users.
- Inventory is synthetic; policy analysis is offline, bounded, schema-validated and has no SSH / Ansible / subprocess calls.
- The API makes no claims about live enforcement or network reachability.
- Do not put this server behind a public reverse proxy or turn it into a production management endpoint.

## Planned security gates before remote execution

- Authentication, CSRF protection where applicable, OIDC, authorization and audit events.
- SSH host key pinning (no silent trust-on-first-use in unattended jobs).
- Dedicated least-privilege remote users, explicit sudo command allowlists, secret vault support.
- A strict host-target allowlist; never accept arbitrary shell commands from policy data.
- Immutable policy revision hashes, review and approval workflows.
- Canary rollout; host-side independently scheduled rollback; path-aware SSH checks.
- Firewall backend ownership checks; preflight detection for Docker/Kubernetes/firewalld conflicts.
- Timeout control, temporary files with safe permissions, audit integrity and redaction.
- Network-restricted, non-root execution worker with minimal capabilities.
- Tests in isolated VMs for management lockout, rollback and SELinux policy regressions.

Production claims must be gated on demonstrated tests; see `docs/SECURITY_AND_ROLLBACK.md`.
