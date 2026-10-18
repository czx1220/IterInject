#!/bin/bash

# Clean Claude Configuration Environment
# Sets up a fresh Claude Code environment with clean config directory
#
# Required environment variables (set in .env or export before running):
#   ANTHROPIC_AUTH_TOKEN  - API key for the target agent
#   ANTHROPIC_BASE_URL   - API base URL
#   ANTHROPIC_MODEL      - Target model name (default: MiniMax-M2.1)
#   CC_BASE_DIR          - Project base directory (default: script's parent)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

export CLAUDE_CONFIG_DIR="${CC_BASE_DIR:-$PROJECT_DIR}/.claude"
export CLAUDE_CURRENT_DIR="${CC_BASE_DIR:-$PROJECT_DIR}"

cd "${CC_BASE_DIR:-$PROJECT_DIR}"

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || echo ./node_modules/.bin/claude)}"

echo "=== Claude Configuration ==="
echo "Config Directory: $CLAUDE_CONFIG_DIR"
echo "Model: ${ANTHROPIC_MODEL:-not set}"
echo "Base URL: ${ANTHROPIC_BASE_URL:-not set}"
echo "Claude Version: $($CLAUDE_BIN --version 2>/dev/null || echo 'unknown')"
echo "Working Directory: $(pwd)"
echo "==========================="

"$CLAUDE_BIN" "$@"
