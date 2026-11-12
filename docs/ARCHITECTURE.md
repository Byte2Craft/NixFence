# Community architecture

```text
Browser (loopback-only) -> FastAPI (cookie auth + CSRF)
                         |    |    |
                         |    |    +--> SQLite (persisted named volume)
                         |    +-------> Offline policy analysis
                         +------------> OpenSSH (strict pinned host keys)
                                         |
                                         v
                                Rocky / Alma / RHEL 9
                                sudo firewalld / SELinux
                                systemd-run rollback timer
```

The SSH backend has **no arbitrary command execution endpoint**. Host management is limited to inspected firewalld ports and SELinux runtime booleans. Remote execution nevertheless relies on a privileged SSH user and broadly capable sudo commands, which must be tightened using a dedicated host-side helper in a later release.

## Staged firewalld operation

1. Verify remote host identity, OS family, active firewalld, zone and both runtime/permanent port states.
2. Atomically reserve the host for one change.
3. Place a root-readable-only rollback script in `/run/nixfence`, and schedule a transient systemd timer.
4. Confirm the timer is `active`. Only then apply the requested runtime port change.
5. Verify runtime state and ask the administrator to confirm or revert.
6. On confirmation, verify timer again; apply the permanent port rule; verify runtime/permanent and cancel the timer.
7. If the SSH session is lost, the host timer attempts to restore original runtime and permanent port states. The control plane marks expired operations `needs_review`, not `reverted`.

No `firewall-cmd --reload` is used; this avoids resetting unrelated transient firewalld rules.

## SELinux booleans

Real `getsebool` reads, runtime-only `setsebool` updates. Confirmation cancels the rollback timer but does not call `setsebool -P`. Persistent SELinux changes and restoration of policy-specific overrides require additional test coverage.
