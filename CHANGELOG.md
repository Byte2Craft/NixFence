# Changelog

## 0.2.0-beta.2 - Image security refresh (not production validated)

- Move the container runtime to current Alpine 3.24 with upgraded OS packages.
- Install non-Kerberos OpenSSH client to avoid the krb5 dependency family.
- Install Python dependencies in a build stage; omit build tooling and pip from runtime.
- Keep app and SSH operations under non-root UID/GID 10001.
- Reject Docker Hub releases on **any** Docker Scout-reported CVE; scan before push.
- Document Docker Hub pull-first Community installation.

**Build, CVE scan and real-host regression testing remain required before publishing.**

## 0.2.0-beta.2 — Community Early Access (not production validated)

- First real SSH host enrollment with strict pinned host-key verification.
- Single-administrator login, HTTP-only cookie sessions and CSRF protection.
- Real Rocky/Alma/RHEL 9 firewalld and SELinux discovery; no synthetic hosts.
- Staged single-port firewalld add/remove operations and permanent confirmation.
- Staged SELinux runtime boolean toggles (NOT persistent), with confirmation.
- Each change requires a verified on-host systemd-run rollback timer.
- SQLite inventory, operation state and audit history.
- Docker Compose local-first install and optional automated Docker Hub publication.

**Caution:** VM failure-injection, sudo scope review and host-OS compatibility testing are required before production use.
