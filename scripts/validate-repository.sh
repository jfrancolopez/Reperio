#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

python3 scripts/validate_repository.py
python3 scripts/check_dependency_licenses.py \
  --registry docs/dependency-registry.json \
  --policy scripts/dependency-license-policy.json
python3 scripts/check_skeleton.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_*.py'
