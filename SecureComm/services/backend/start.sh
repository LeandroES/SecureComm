#!/usr/bin/env sh
set -euo pipefail

alembic upgrade head || true

exec "$@"