# Quickstart — Byte2craft NixFence alpha

## Prerequisites

Docker Engine with the Compose plugin or Docker Desktop. A local browser.

## Launch

```bash
docker compose up --build -d
docker compose ps
```

Browse to **http://127.0.0.1:8080**.

You can open **Linux Hosts** and **SELinux** to inspect fictional example infrastructure. Open **Policy Playground** to see the real, deterministic JSON validation engine. Try changing `source` to `0.0.0.0/0` on the SSH ACCEPT rule and analyze again.

## API test

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS -X POST http://127.0.0.1:8080/api/v1/policies/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/policies/web-prod.json
```

## Stop

```bash
docker compose down
```

## Development without Docker

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
make test
make run
```

## Safety

This preview is intentionally unauthenticated and must only be used on loopback. It stores no SSH keys and cannot alter real hosts. Do not customize the bind address to `0.0.0.0` for network exposure. The quickstart is a product demo, not a production install guide.

