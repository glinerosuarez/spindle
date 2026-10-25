#!/usr/bin/env bash
# Usage: demo/run_cursor.sh before|after|remote
set -euo pipefail
cd "$(dirname "$0")/$1"
[ -f .env ] && set -a && source .env && set +a
# Cursor CLI discovers project configuration (.cursor/mcp.json and .cursor/cli.json)
# by resolving `git rev-parse --show-toplevel`. Without a local .git directory, Cursor
# climbs to the parent spindle-app root and misses demo MCP and permission configs.
# Initializing a local repo establishes demo/{before,after,remote} as the project root.
[ -d .git ] || git init -q
exec cursor-agent --model "${SPINDLE_DEMO_MODEL:-grok-4.7-medium-fast}" --approve-mcps --trust --sandbox enabled
