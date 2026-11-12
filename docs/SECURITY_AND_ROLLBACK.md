# Security and independent rollback

**This beta is not a production safety guarantee.** Real host integration needs failure-injection VM tests and security review before production use.

## Controls included

- SSH requires previously pinned host keys and key-based login; there is no option to trust an unknown host automatically.
- Browser UI has a single administrator, HTTP-only cookie session, CSRF token and strict origin checking for write requests.
- A change is never executed before the host has accepted and activated a transient systemd rollback timer.
- The rollback script restores the old runtime and permanent state for the specified firewalld port, without reloading unrelated zones or rules.
- SELinux boolean toggles are runtime-only; the timer reverts to the original runtime value unless confirmed.
- Operations whose deadline passes are marked `needs_review` until independently verified. This avoids falsely claiming recovery.

## Important gaps

- `sudo -n /bin/sh` and privileged file/timer operations give the SSH identity broad root capability. A constrained root helper is required for the intended least-privilege design.
- No separate controller redundancy or watchdog confirmation service.
- No tested OS support outside Rocky/Alma/RHEL 9; no SSH-loss/reboot chaos test evidence yet.
- State changes by another administrator during an open transaction may conflict with the rollback.
- Remote OS crash, stopped firewalld, systemd failure or host compromise can invalidate safety assumptions.
- No production authorization model beyond one administrator; protect the local API and secret mounts.

## VM test scenario

1. Use a disposable Linux 9 VM with out-of-band console access and a dedicated SSH user.
2. Record `firewall-cmd --zone=public --list-ports` and `firewall-cmd --permanent --zone=public --list-ports`.
3. Stage a port addition with a 180-second timer. Check the matching `nixfence-rb-*.timer` on the VM.
4. Intentionally disconnect controller networking or stop the Docker container before confirmation.
5. After expiry verify the port state returned to baseline on the VM. Repeat with a removal, an SSH-session disruption, a firewalld restart and an unexpected controller reboot.
6. Review systemd journal output and audit metadata. Never treat timeouts alone as proof of successful rollback.
