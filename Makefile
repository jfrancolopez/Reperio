SHELL := /bin/bash

PYTHON ?= python3

.PHONY: help validate secret-scan workflow-lint versions \
	dev-install format format-check lint type-check unit-test \
	frontend-test schema-check docs-check config-check quality

help:
	@echo "Reperio repository commands"
	@echo "  make validate       Run every dependency-free repository policy check"
	@echo "  make secret-scan    Run a checksum-verified Gitleaks worktree/history scan"
	@echo "  make workflow-lint  Download a checksum-verified Actionlint and lint CI"
	@echo "  make versions       Report every package version"
	@echo "  make dev-install    Install pinned developer quality tools"
	@echo "  make format         Format Python files with ruff (rewrites files)"
	@echo "  make format-check   Verify Python files are formatted"
	@echo "  make lint           Lint with ruff (never rewrites files)"
	@echo "  make type-check     Static type-check with mypy"
	@echo "  make unit-test      Run unit tests with pytest"
	@echo "  make frontend-test  Run the frontend placeholder gate"
	@echo "  make schema-check   Run JSON and schema/policy compatibility checks"
	@echo "  make config-check   Run configuration contract and combination checks"
	@echo "  make docs-check     Run documentation link and backlog checks"
	@echo "  make quality        Aggregate quality target (all of the above)"

validate:
	./scripts/validate-repository.sh

secret-scan:
	./scripts/scan-secrets.sh

workflow-lint:
	./scripts/lint-workflows.sh

versions:
	$(PYTHON) scripts/report-versions.py

dev-install:
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format .

format-check:
	$(PYTHON) -m ruff format --check .

lint:
	$(PYTHON) -m ruff check .

type-check:
	$(PYTHON) -m mypy .

unit-test:
	$(PYTHON) -m pytest

frontend-test:
	$(PYTHON) scripts/frontend-test.py

schema-check:
	$(PYTHON) scripts/schema-check.py

config-check:
	$(PYTHON) scripts/config_validator.py

docs-check:
	$(PYTHON) scripts/docs-check.py

quality: format-check lint type-check unit-test frontend-test schema-check docs-check config-check
