# NixFence Community architecture

NixFence uses a small modular application for the developer preview. The present source tree consists of a browser UI, read-only synthetic API and JSON policy analyzer. **There is no remote execution or database in this release.**

## Current implementation

```text
Browser (local-only) -> FastAPI -> static synthetic host/policy fixtures
                                  -> Pydantic policy schema + offline analyzer
```

The Docker Compose service binds to the host's `127.0.0.1:8080`. The container is non-root and read-only. The API has no authentication and must remain inaccessible to untrusted networks.

## Target Community architecture (not yet implemented)

```text
Browser + CLI
    |
Authenticated versioned REST API
    |
Inventory | Policy model | Validation | Revision history | Audit
    |                              |
Observed state                 Desired state
    |                              |
    +--- Isolated execution worker / Ansible Runner
                    |
             Verified SSH
                    |
  Linux hosts: firewalld or nftables, SELinux
   (no per-server web administration agent)
```

### Design contracts

- Frontend policy edits must never be translated directly into shell commands.
- Host-target selection is different from packet source/destination matching.
- Backend adapters must reject unsupported semantics, not silently approximate them.
- Actual observed state must be tracked separately from approved desired state.
- Start with a single supported backend; detect other firewall owners before any changes.
- Require explicit intent and authorization for every write operation.
- Avoid a mandatory vendor cloud, online license server or Kubernetes cluster for Community.
- A rollback timer must be independent of the management API and tested with complete SSH loss.
- Every proposed change must show its diff, scope, verification status and recovery path.

## Example future adapter protocol

```python
from typing import Protocol

class FirewallAdapter(Protocol):
    def discover(self, host): ...
    def validate(self, policy): ...
    def render(self, policy): ...
    def stage(self, host, rendered): ...
    def verify(self, host, expected): ...
    def rollback(self, host, staged): ...
```

These are **design sketches**, not executable adapters in this alpha.
