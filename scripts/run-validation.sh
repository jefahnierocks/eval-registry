#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 scripts/check_agent_contract.py
python3 scripts/validate_repository.py
python3 -m unittest discover -s tests -v
ruff check .
ruff format --check .
python3 scripts/check_repository_security.py
git diff --check
