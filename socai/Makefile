.PHONY: run-api lint format test

run-api:
	uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

lint:
	ruff check .
	mypy .

format:
	black .
	ruff format .

test:
	pytest
