# Release status — v0.1.0-alpha.0

**Technical preview. Not for production.**

## Included

- Local web console with visible Byte2craft project attribution.
- Synthetic host inventory, example policy sets and example SELinux posture.
- Typed JSON policy validation and a preliminary offline analyzer.
- Local-only FastAPI endpoints and OpenAPI documentation.
- Docker Compose demo configuration and automated tests.

## Not included

- SSH host enrollment or discovery; live firewall or SELinux reads/writes.
- Authentication, user roles, database persistence or revision history.
- Live deployment, canary rollout, independent host-side rollback or audit trails.
- Scheduled audits, security alerts, compliance reporting and paid editions.

The policy checker uses early heuristics. A clean result is **not proof** that any policy is safe for production deployment. Do not expose the demo on a public interface.
