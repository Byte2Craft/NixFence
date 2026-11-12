.PHONY: run test lint compose-up compose-down

run:
	NIXFENCE_DB=$(CURDIR)/data/nixfence.sqlite3 \
	NIXFENCE_ADMIN_PASSWORD_FILE=$(CURDIR)/secrets/admin_password \
	NIXFENCE_SSH_KEY_FILE=$(CURDIR)/secrets/id_ed25519 \
	NIXFENCE_KNOWN_HOSTS=$(CURDIR)/secrets/known_hosts \
	NIXFENCE_WEB_DIR=$(CURDIR)/web \
	PYTHONPATH=src uvicorn nixfence.api:create_app --factory --host 127.0.0.1 --port 8080

test:
	PYTHONPATH=src pytest -q

lint:
	ruff check src tests

compose-up:
	docker compose -f compose.yaml -f compose.build.yaml up -d --build

compose-down:
	docker compose down
