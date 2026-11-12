# NixFence Community security policy

NixFence `0.2.0-beta.1` performs real privileged Linux operations but **has not been independently audited or production-tested**. Keep it restricted to local evaluation and disposable hosts.

- Do not expose the management API to the public internet; default Docker binding is loopback-only.
- Require verified SSH host keys; never use `StrictHostKeyChecking=no`.
- Restrict administrator password, SSH private key, known_hosts and database backups.
- Test the on-host systemd rollback timer before touching a real operational firewall.
- This release's broadly privileged SSH/sudo model is a known risk and must be redesigned before production.
- Do not submit vulnerabilities, credentials or target IP addresses to public Issues.

For private reports, use GitHub's **Private vulnerability reporting** if enabled for the repository, or contact Byte2craft using the [official website](https://byte2craft.com/contact-us/). Do not publish exploitation steps before a fix is available.
