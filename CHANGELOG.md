# Changelog

## 0.2.0-beta.1 — Community Early Access (not production validated)

- First real SSH host enrollment with strict pinned host-key verification.
- Single-administrator login, HTTP-only cookie sessions and CSRF protection.
- Real Rocky/Alma/RHEL 9 firewalld and SELinux discovery; no synthetic hosts.
- Staged single-port firewalld add/remove operations and permanent confirmation.
- Staged SELinux runtime boolean toggles (NOT persistent), with confirmation.
- Each change requires a verified on-host systemd-run rollback timer.
- SQLite inventory, operation state and audit history.
- Docker Compose local-first install and optional automated Docker Hub publication.

**Caution:** VM failure-injection, sudo scope review and host-OS compatibility testing are required before production use.
