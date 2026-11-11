# NixFence Community roadmap

This roadmap is a proposed engineering direction, **not a promise of production readiness or delivery dates**. The public repository contains the open-source Community edition only.

## M0 — Current technical alpha

- Local, Byte2craft-branded web demo backed by synthetic inventory.
- Typed JSON firewall-policy model with preliminary offline warnings.
- OpenAPI endpoint, example policy, automated tests and Docker Compose.
- Demo binds to `127.0.0.1` and has no authentication; never expose publicly.

## M1 — Verified read-only discovery

- Safe SSH onboarding with pinned host identities and explicit authorization.
- Supported Rocky Linux, AlmaLinux and RHEL version matrix.
- Read-only firewalld/SELinux state detection.
- User authentication and secure secret-handling before remote discovery is enabled.

## M2 — Safe host policy management

- One explicitly supported firewall adapter, typed editor and exact diff.
- Immutable desired revisions with canary rollout.
- Independent host-side rollback validated by fault-injection tests.
- SELinux booleans and modes with strict platform capability checks.

## M3 — Stable Community release

- Published compatibility matrix, upgrade path and backup/restore tests.
- Auditable basic changes, portable policy export and manual drift comparison.
- API documentation, accessibility and security review.

Contributions are welcome. Features are not considered shipped until implemented, documented and tested.
