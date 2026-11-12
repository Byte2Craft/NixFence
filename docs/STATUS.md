# NixFence Community v0.2.0-beta.1 — Verified implementation status

This is **real host operations code**, not a simulated demo. It has not yet passed real Rocky/Alma/RHEL VM failure-injection tests or an independent security review and is therefore **not production-ready**.

## Implemented

- Single administrator, session cookie, CSRF token and login rate limiting.
- Real SSH connections using OpenSSH `StrictHostKeyChecking=yes` and a pinned known_hosts file.
- Enrollment fails unless the host can be inspected (only Rocky/Alma/RHEL 9 with active firewalld).
- Real firewalld zone and port inspection.
- Real port add/remove to the runtime ruleset; confirmation commits one port to permanent rules.
- Real SELinux boolean read/list, runtime toggling and confirmation (runtime-only).
- Before any change: schedule a host-side independent rollback using systemd-run and verify active timer.
- Manual revert and inspection; late/failed changes are marked `needs_review`, never assumed recovered.
- Durable SQLite host inventory, operations and audit metadata.
- Offline JSON policy analyzer retained (not wired to live apply).

## Not yet provided

- A tightly scoped on-host sudo helper or audited least-privilege sudo policy.
- Firewall rich-rule / zone reconfiguration, nftables adapters, bulk deployments or host groups.
- SELinux persistent boolean modification (runtime-only intentionally).
- Multi-user RBAC/SSO, approvals, full audit tamper-evidence, credential rotation UI.
- High availability, migrations, incremental backups, cross-platform target support.
- Automated host VM/SSH-loss rollback verification and full integration tests.

## Safety claim limitation

The systemd-run timer is designed to run even after SSH drops. This property still needs to be tested on supported real VMs. It cannot protect against a stopped systemd manager, OS crash, firewalld daemon failure, policy conflicts or malicious host administrators. Never disable host key verification or publish the unaudited control plane on an internet-facing port.
