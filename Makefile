.PHONY: run test lint compose-up compose-down
run:
	PYTHONPATH=src uvicorn nixfence.api:app --host 127.0.0.1 --port 8080

test:
	PYTHONPATH=src pytest -q

lint:
	ruff check src tests

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
