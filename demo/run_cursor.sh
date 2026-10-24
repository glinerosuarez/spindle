#!/usr/bin/env bash
# Usage: demo/run_cursor.sh before|after
set -euo pipefail
cd "$(dirname "$0")/$1"
[ -d .git ] || git init -q
exec cursor-agent --model "${SPINDLE_DEMO_MODEL:-grok-4.7-medium-fast}" --approve-mcps --trust --sandbox enabled
