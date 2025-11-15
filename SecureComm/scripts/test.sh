#!/usr/bin/env bash
set -euo pipefail

npm install
npm run test --workspaces

python3 -m venv .venv
source .venv/bin/activate
pip install -e services/backend[dev]
pytest services/backend/tests