.PHONY: help install dev run test lint format typecheck check migrate revision clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install runtime + dev dependencies
	pip install -e ".[dev]"
	pre-commit install

run:  ## Run the API locally with hot reload
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:  ## Run the test suite
	pytest

test-cov:  ## Run tests with coverage report
	pytest --cov=app --cov-report=term-missing --cov-report=html

lint:  ## Lint with ruff
	ruff check app tests

format:  ## Format with ruff
	ruff format app tests
	ruff check --fix app tests

typecheck:  ## Type-check with mypy
	mypy app

check: lint typecheck test  ## Run all checks

revision:  ## Create a new Alembic revision (use M="message")
	alembic revision --autogenerate -m "$(M)"

migrate:  ## Apply Alembic migrations
	alembic upgrade head

downgrade:  ## Roll back one Alembic revision
	alembic downgrade -1

clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage build dist *.egg-info
