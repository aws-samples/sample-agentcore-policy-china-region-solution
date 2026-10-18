#!/usr/bin/env bash
# Run the demo. Usage: scripts/demo.sh [scenario|all] [--region cn|global|both] [-v]
cd "$(dirname "$0")/.."
source scripts/lib.sh
ensure_venv
exec $PY scripts/demo.py "$@"
