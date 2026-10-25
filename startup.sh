#!/bin/bash
set -e

# Detect app directory dynamically
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${APP_DIR}/src:${PYTHONPATH}"

echo "Starting Spindle Cloud from ${APP_DIR} on port 8000..."
exec python -m uvicorn spindle.cloud:app --host 0.0.0.0 --port 8000
