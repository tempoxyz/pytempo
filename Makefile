.PHONY: install lint format format-check test check all fix docs docs-clean

install:
	uv sync --dev

lint:
	uv run ruff check .

fix:
	uv run ruff check --fix .
	uv run ruff format .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

test:
	uv run pytest -v

check: lint format-check test

all: install check

docs:
	uv run --group docs sphinx-build docs docs/_build

docs-clean:
	rm -rf docs/_build
