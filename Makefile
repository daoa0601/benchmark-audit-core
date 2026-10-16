.PHONY: install sync lint format typecheck test check

install:
	@command -v uv >/dev/null 2>&1 || { echo "uv is required" >&2; exit 1; }
	uv sync --all-extras
	uv run pre-commit install

sync:
	uv sync --all-extras

lint:
	uv run ruff check .

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run basedpyright

test:
	uv run pytest -v --cov=benchmark_audit_core --cov-report=term-missing

check:
	uv run ruff format --check .
	uv run ruff check .
	uv run basedpyright
	uv run pytest -v --cov=benchmark_audit_core --cov-report=term-missing
