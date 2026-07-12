#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CORTASENTRY_CONFIG:-${1:-}}"
BIN="${CORTASENTRY_BIN:-$(command -v cortasentry || true)}"
if [[ -z "$CONFIG" || ! -f "$CONFIG" ]]; then
  echo "usage: CORTASENTRY_CONFIG=/absolute/path/cortasentry.yaml ./scripts/install-mcp.sh" >&2
  exit 2
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "cortasentry binary not found; set CORTASENTRY_BIN" >&2
  exit 2
fi
CONFIG="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"
installed=0
if command -v codex >/dev/null; then
  codex mcp add cortasentry --env "CORTASENTRY_CONFIG=$CONFIG" -- "$BIN" mcp
  echo "Installed CortaSentry MCP for Codex"
  installed=1
fi
if command -v claude >/dev/null; then
  claude mcp add cortasentry --scope local --env "CORTASENTRY_CONFIG=$CONFIG" -- "$BIN" mcp
  echo "Installed CortaSentry MCP for Claude Code"
  installed=1
fi
if [[ "$installed" = 0 ]]; then
  echo "Neither codex nor claude CLI was found. See docs/MCP.md for manual configuration." >&2
  exit 1
fi
