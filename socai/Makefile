.PHONY: lint format test

lint:
	ruff check .
	mypy .

format:
	black .
	ruff format .

test:
	pytest
