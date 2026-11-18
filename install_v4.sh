#!/usr/bin/env bash
# Upgrade TP-Link MCP service safely. Never writes switch configuration.
set -euo pipefail
umask 077
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/server.py"
DST="$HOME/.local/share/tplink-mcp/server.py"
PY="$HOME/tplink-env/bin/python"
UNIT=tplink-mcp.service

if [[ ! -f "$SRC" || ! -f "$DST" || ! -x "$PY" ]]; then
  echo 'Existing TP-Link MCP or Python environment missing. No changes made.' >&2
  exit 1
fi

echo 'Syntax check and live READ-ONLY identity test...'
"$PY" -m py_compile "$SRC"
"$PY" "$SRC" --self-test

backup="$DST.pre-v4-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$DST" "$backup"
install -m 0644 "$SRC" "$DST"
rollback() {
  echo 'Service startup failed; restoring previous server.' >&2
  cp -p "$backup" "$DST"
  systemctl --user restart "$UNIT" || true
}
if ! systemctl --user restart "$UNIT"; then rollback; exit 1; fi
sleep 2
if ! systemctl --user is-active --quiet "$UNIT"; then rollback; exit 1; fi
printf '\nTP-Link MCP v4 started. Previous server saved: %s\n' "$backup"
echo 'Existing OpenAI tunnel not modified. No switch settings were changed.'
echo 'Refresh TP-Link custom MCP in ChatGPT, then call switch_capabilities.'
