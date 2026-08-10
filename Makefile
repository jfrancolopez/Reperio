SHELL := /bin/bash

.PHONY: help validate secret-scan workflow-lint

help:
	@echo "Reperio repository commands"
	@echo "  make validate     Run every dependency-free repository policy check"
	@echo "  make secret-scan  Run a checksum-verified Gitleaks worktree/history scan"
	@echo "  make workflow-lint  Download a checksum-verified Actionlint and lint CI"

validate:
	./scripts/validate-repository.sh

secret-scan:
	./scripts/scan-secrets.sh

workflow-lint:
	./scripts/lint-workflows.sh
