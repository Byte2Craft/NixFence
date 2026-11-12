<div align="center">

# 🛡️ NixFence Community

### Real Linux host operations, without the shell marathon.

**Open-source Linux firewalld and SELinux control plane by [Byte2craft](https://byte2craft.com)**

[Product page](https://byte2craft.com/nixfence/) · [Quickstart](docs/QUICKSTART.md) · [Host preparation](docs/HOST_PREPARATION.md) · [Security limitations](docs/STATUS.md) · [Docker Hub publishing](docs/DOCKERHUB.md)

**v0.2.0-beta.1 / Community Early Access** · **Apache-2.0** · **Self-hosted**

</div>

> [!WARNING]
> **REAL REMOTE OPERATIONS — NOT YET PRODUCTION-VALIDATED.** Unlike the v0.1 synthetic demo, this beta uses verified SSH to inspect and modify real Linux hosts. It has *not* passed independent security review or VM failure-injection tests. Do not deploy to production or expose the management UI to the internet. Test rollback through an independent console on disposable VMs first.

## What works today

- **Real host enrollment:** SSH with pinned host keys (`StrictHostKeyChecking=yes`), no unverified-host acceptance, no per-host web agent.
- **Supported target scope:** Rocky Linux 9 / AlmaLinux 9 / RHEL 9 with running firewalld, SELinux, systemd and passwordless privileged commands.
- **Live read-only discovery:** Linux version, SELinux enforcement mode, active/default firewalld zones and real port/service state.
- **Real firewall changes:** Add/remove one firewalld port allowance in the runtime ruleset; confirm to persist that same port, or revert.
- **Real SELinux boolean changes:** Read booleans, stage a runtime toggle and confirm or revert; confirmed SELinux values are **runtime-only**.
- **Independent host rollback timer:** Staging first schedules and verifies a systemd transient timer on the target host. The control plane does not assume a timed-out change was recovered without checking the host.
- **Authentication and history:** Single-admin login, server-side sessions, HTTP-only cookies, CSRF, login throttling, SQLite audit records.
- **Offline policy analyzer:** JSON policy validation remains separate from live deployment; analyzer results never trigger SSH commands.

## Fast local installation (Docker)

1. Clone the repository and generate credentials:

```bash
git clone https://github.com/Byte2Craft/NixFence.git
cd NixFence
python scripts/bootstrap.py
```

2. Set up a dedicated host SSH user and **independently verify** the host's SSH public key before adding it to `secrets/known_hosts`. Ensure the `secrets/` directory and mounted files are readable by container GID `10001` but not world-readable. [Full preparation](docs/HOST_PREPARATION.md).

3. Build locally for evaluation (does not require Docker Hub):

```bash
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

Open **http://127.0.0.1:8080** on the Docker machine, sign in as `admin` with the bootstrap password, then enroll a real host. The host inventory is empty until you enroll and verify one.

4. **Once the image has been published** to Docker Hub, deploy without building:

```bash
docker compose pull
docker compose up -d
```

Pulls: `byte2craft/nixfence-community:0.2.0-beta.1`. This tag does **not** exist merely because the package was prepared; the project publisher must push it first using the provided [GitHub Actions workflow](docs/DOCKERHUB.md).

## Security boundaries and limitations

- The service listens on Docker host `127.0.0.1:8080` by default. For remote operator access use `ssh -L 8080:127.0.0.1:8080 admin@docker-host`.
- The SSH runner rejects unknown or changed host keys. Every target has to be explicitly enrolled and pass real inspections. Only OpenSSH key authentication is used.
- Any staged change requires the remote systemd timer to become active. Firewalld changes are initially **runtime-only**, then made permanent explicitly on confirmation; no blanket `firewall-cmd --reload` is performed.
- **Unresolved safety risk:** This beta needs privileged `sudo` operations such as `tee`, `systemd-run` and `/bin/sh`. These are broad root privileges; a tightly constrained root helper and independent security review are required before production use.
- Only one in-flight change per host; no multi-user RBAC, host groups, bulk deploy, arbitrary firewall syntax, nftables adapter, persistent SELinux toggles or HA yet.
- An unreachable host, malfunctioning systemd timer or crash can defeat rollback. Expired changes are labeled `needs_review`, never automatically declared safe.

See the [full status](docs/STATUS.md), [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).

## Project layout

```text
src/nixfence/    FastAPI, SSH transport, auth, transactions, policy analyzer
web/             Real host-management browser console
scripts/         Bootstrap credentials
compose.yaml     Docker Hub pull/compose deployment
compose.build.yaml  Local image build override
Dockerfile       Unprivileged container with OpenSSH client
.github/workflows/ CI and opt-in tag-triggered Docker Hub publishing
docs/            Installation, host preparation, safety and roadmap
tests/           Unit and API tests with simulated SSH command results
```

## Community license and contributions

NixFence Community code is [Apache-2.0](LICENSE). Contributions and issues are in English. Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Do not submit secrets, private inventories or unlicensed third-party benchmark content.

**Built for engineers. Crafted by [Byte2craft](https://byte2craft.com).**
