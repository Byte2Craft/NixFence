<div align="center">

# 🛡️ NixFence

### Linux security, without the shell marathon.

**NixFence Community — an open-source project by [Byte2craft](https://byte2craft.com)**

[Website](https://byte2craft.com/nixfence/) · [Quickstart](docs/QUICKSTART.md) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md) · [Contributing](CONTRIBUTING.md)

**Technical Alpha `v0.1.0-alpha.0`** · **Apache-2.0** · **Self-hosted**

</div>

> [!WARNING]
> **TECHNICAL PREVIEW ONLY — NOT PRODUCTION READY.** This repository is an unauthenticated, local-only demo containing synthetic Linux hosts and an offline firewall-policy analyzer. It **does not** connect to hosts over SSH, manage live firewall/SELinux configuration, deploy policies, implement access control or provide rollback. **Never expose the demo to the public network or use it as a production security management service.**

## What is NixFence?

NixFence is an open-source effort to make Linux **host firewall** and **SELinux** administration easier to understand. The goal is a lightweight, agentless control plane for engineers who need to review security state, model policies and eventually apply verified changes across multiple Linux servers. No per-host Webmin or Cockpit installation is planned.

**Current reality:** a working technical preview of the interface and an offline JSON policy analyzer. Remote management and safe deployment are future milestones. All example hosts use synthetic, documentation-only IP addresses.

## Quickstart — local demo

Install Docker with Docker Compose, then:

```bash
git clone https://github.com/Byte2Craft/NixFence.git
cd NixFence
docker compose up --build -d
```

Open **http://127.0.0.1:8080**. The demo runs on loopback only and needs **no credentials or SSH keys**. Try **Policy Playground** for read-only JSON policy checks. Run `docker compose down` to stop it.

For Python development without Docker, see [Quickstart](docs/QUICKSTART.md). The HTTP API is documented at `http://127.0.0.1:8080/api/docs` after starting the app.

## Implemented today

| Area | Status |
| --- | --- |
| Byte2craft-branded responsive Community console | Implemented demo |
| Synthetic Linux inventory and example SELinux status | Implemented demo |
| JSON firewall policy schema and validation endpoint | Implemented offline |
| Warnings for exposed SSH/database ports, duplicate and shadowed rules | Initial heuristics |
| OpenAPI, tests and Docker Compose | Available |
| Actual SSH enrollment / read-only host discovery | **Not implemented** |
| Live firewalld / nftables or SELinux changes | **Not implemented** |
| Authentication, approval workflow, rollback and audit history | **Not implemented** |
| Continuous compliance monitoring or alarms | **Not implemented** |

The preliminary analyzer is **not** a reachability proof, a complete ruleset compiler or permission to deploy a policy. See [Release status](docs/STATUS.md).

## Test the analyzer

```bash
curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/policies/web-prod.json
```

The service returns a normalized analysis and preliminary findings. It performs **no SSH, Ansible, firewall or SELinux operations**.

## Architecture direction

```text
Browser / Community Web Console
              |
              v
     Versioned FastAPI endpoint
              |
              v
      Typed policy analyzer
              |
       (offline demo now)

Future Community components (not shipped yet):
Verified SSH discovery -> firewalld/SELinux adapters
  -> reviewed changes -> canary -> independent rollback
```

Community is Apache-2.0 and may be used or modified commercially subject to the license. The open core is intended to remain genuinely useful without arbitrary host-count limits or an online license server. **Essential change-safety and recovery mechanisms will not be reserved for paid editions.** Separate commercial products and optional services may be introduced by Byte2craft in the future; they are **not** contained in this repository. The full product overview lives at [byte2craft.com/nixfence](https://byte2craft.com/nixfence/).

## Project layout

```text
src/nixfence/   Community API, sample data, typed models and offline analyzer
web/            Local Community demo UI (plain HTML, CSS and JavaScript)
examples/       Synthetic inventory and firewall policy examples
tests/          Automated tests
.github/        CI and contribution templates
docs/           Quickstart, architecture, roadmap, status and security design
```

No internal marketing plans, pricing strategies, proprietary Enterprise modules, licensed benchmark content or customer configurations are included.

## Security and contributions

Use **English** for issues, pull requests and documentation. Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities, [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes and [TRADEMARKS.md](TRADEMARKS.md) for brand usage. **Do not post credentials, private inventories or production screenshots.**

No CIS Benchmark content is bundled or certified by this project. All third-party benchmark use would require the necessary rights and accurate labeling.

## License

NixFence Community source code is licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 Byte2craft contributors. The code license is distinct from the right to imply Byte2craft endorsement through product names or logos; see [TRADEMARKS.md](TRADEMARKS.md).

---

**Built for engineers. Crafted by [Byte2craft](https://byte2craft.com).** · [NixFence product page](https://byte2craft.com/nixfence/)
