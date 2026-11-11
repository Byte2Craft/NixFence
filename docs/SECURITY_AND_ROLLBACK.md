# Threat model and safe deployment protocol (design; not implemented)

NixFence's most dangerous failure mode is self-lockout across a managed fleet. The second is hidden privilege escalation or credential exposure from the control plane.

## Trust zones

1. Browser is untrusted. UI submissions are data, never executable commands.
2. API enforces authentication/authorization and receives structured, versioned policy only.
3. Worker is isolated, non-root where possible, and has access only to the SSH credentials needed for its job.
4. Host operations use a dedicated sudo policy with bounded commands, verified host keys and explicit target IDs.
5. Git and audit database may have privileged operator data; secrets must not be logged or exported.

## Rollout protocol

- Observe actual firewall ownership, existing management routes, SSH listening address, IPv4/IPv6 and container orchestration conflicts.
- Take a versioned snapshot of the relevant ruleset and relevant metadata. Capture *which backend owns which table*.
- Validate diff and semantic translation. Never promise full simulation of packet path from policy heuristics alone.
- Stage candidate configuration and schedule a **host-local independent rollback** (e.g. a carefully tested systemd transient service/timer), verified to exist before commit. Must survive loss of control plane network.
- Apply the candidate atomically where the backend supports it. Ensure no rule table managed by another service is erased.
- Test SSH + separate application health from the management CIDRs and confirm expected policy state, using an independent path where feasible.
- Cancel the rollback only after positive verification. Log remote host proof, revision hash, timestamp and actor.
- First do canary rollout; pause on any failure, then continue in limited batches.
- If the control connection fails, the host-local job restores the snapshot autonomously. Log partial failure if the controller cannot verify host restoration.

## SELinux-specific safety

- Default to `enforcing`; disabling must not be a routine UI toggle.
- SELinux booleans, port labels and contexts use typed allowlists and explicit affected-service descriptions.
- `semanage fcontext` registration does not automatically re-label existing files. `restorecon` is a separate, reviewable step.
- Policy module installation and context recursion can change access far beyond a single rule and require separate privileges.
- Mode changes, package state and service impact may require reboot or special platform checks.

## Verification test matrix before GA

1. SSH is blocked mid-rollout and rollback restores access without controller connectivity.
2. Host reboots before/after commit; rollback and audit state are consistent.
3. IPv6 remains reachable only as intended, even when IPv4 policy looks correct.
4. Container networking (Docker/Kubernetes) and libvirt rule ownership is not overwritten.
5. Different RHEL-family versions, firewalld backends and SELinux states are covered.
6. Partial fleet success emits per-target failures, no misleading all-green status.
7. Worker loses secrets or broker, job never continues with broader authority.
8. Unsafe policy cannot be applied by bypassing UI through the REST API.

## Launch gates

No auth → **no live host access**. No tested local rollback → **no write adapter**. No audited and versioned policy revision → **no production deployment**. These are architectural rules, not marketing options.
