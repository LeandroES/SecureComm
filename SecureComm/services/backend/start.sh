#!/bin/sh

set -eu

alembic upgrade head || true

exec "$@"