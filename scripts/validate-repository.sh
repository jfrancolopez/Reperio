#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

python3 scripts/validate_repository.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
