#!/usr/bin/env bash
set -euo pipefail

npm install
npm run lint --workspaces

python3 -m venv .venv
source .venv/bin/activate
pip install -e services/backend[dev]
ruff check services/backend/securecomm_backend