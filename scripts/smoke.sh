#!/usr/bin/env bash
# Copyright (c) 2026 Nrupal Akolkar
# SPDX-License-Identifier: Apache-2.0
#
# GMSI-124 operator-surface smoke proof for Guardian Mesh.
#
# This is test scaffolding, not shipped runtime. It assumes guardian-meshd is
# already running at the endpoint and that the gm and gm-mcp binaries are built
# (target/release is preferred over target/debug).

set -u

ENDPOINT="${1:-http://127.0.0.1:50051}"
UNREACHABLE_ENDPOINT="http://127.0.0.1:59999"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

pick_bin() {
  local name="$1"
  local candidate
  for candidate in \
    "$ROOT_DIR/target/release/$name" \
    "$ROOT_DIR/target/release/$name.exe" \
    "$ROOT_DIR/target/debug/$name" \
    "$ROOT_DIR/target/debug/$name.exe"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

GM="$(pick_bin gm)"
GM_MCP="$(pick_bin gm-mcp)"

if [ -z "$GM" ] || [ -z "$GM_MCP" ]; then
  echo "FAIL binaries: gm='$GM' gm-mcp='$GM_MCP' (build target/release or target/debug first)"
  exit 1
fi

TMPDIR_SMOKE="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_SMOKE"' EXIT

SESSION_FILE="$TMPDIR_SMOKE/gm-session.json"
PROOF_FILE="$TMPDIR_SMOKE/gm-proof.json"
TAMPERED_PROOF="$TMPDIR_SMOKE/gm-proof-tampered.json"

FAILED=0

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  FAILED=$((FAILED + 1))
}

json_field() {
  local file="$1"
  shift
  python3 - "$file" "$@" <<'PY' 2>/dev/null
import json
import sys

try:
    with open(sys.argv[1]) as handle:
        value = json.load(handle)
    for key in sys.argv[2:]:
        value = value[key]
except Exception:
    sys.exit(2)

if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
else:
    print(value)
PY
}

# Leg 1: gm health.
if "$GM" health --endpoint "$ENDPOINT" >"$TMPDIR_SMOKE/health.json" 2>"$TMPDIR_SMOKE/health.err"; then
  pass "gm health"
else
  fail "gm health"
fi

# Leg 2: gm handshake.
if "$GM" handshake --session-file "$SESSION_FILE" --endpoint "$ENDPOINT" \
  >"$TMPDIR_SMOKE/handshake.json" 2>"$TMPDIR_SMOKE/handshake.err"; then
  pass "gm handshake"
else
  fail "gm handshake"
fi

# Leg 3: gm evaluate TOOL_CALL -> ALLOW.
if "$GM" evaluate --action-type TOOL_CALL --context smoke --target gm \
  --session-file "$SESSION_FILE" --proof-out "$PROOF_FILE" --endpoint "$ENDPOINT" \
  >"$TMPDIR_SMOKE/evaluate.json" 2>"$TMPDIR_SMOKE/evaluate.err"; then
  verdict="$(json_field "$TMPDIR_SMOKE/evaluate.json" verdict)"
  if [ "$verdict" = "ALLOW" ]; then
    pass "gm evaluate TOOL_CALL"
  else
    fail "gm evaluate TOOL_CALL"
  fi
else
  fail "gm evaluate TOOL_CALL"
fi

# Leg 4: gm verify -> valid.
if "$GM" verify --proof-file "$PROOF_FILE" --session-file "$SESSION_FILE" \
  --endpoint "$ENDPOINT" >"$TMPDIR_SMOKE/verify.json" 2>"$TMPDIR_SMOKE/verify.err"; then
  valid="$(json_field "$TMPDIR_SMOKE/verify.json" valid)"
  if [ "$valid" = "true" ]; then
    pass "gm verify"
  else
    fail "gm verify"
  fi
else
  fail "gm verify"
fi

# Leg 5: gm verify with one hex character of the proof payload flipped.
if python3 - "$PROOF_FILE" "$TAMPERED_PROOF" <<'PY'
import json
import sys

source, destination = sys.argv[1], sys.argv[2]
with open(source) as handle:
    proof = json.load(handle)
payload = proof["payload"]
if not isinstance(payload, str) or not payload:
    raise SystemExit("proof payload is empty or not a string")
replacement = "1" if payload[0] != "1" else "0"
proof["payload"] = replacement + payload[1:]
with open(destination, "w") as handle:
    json.dump(proof, handle)
PY
then
  "$GM" verify --proof-file "$TAMPERED_PROOF" --session-file "$SESSION_FILE" \
    --endpoint "$ENDPOINT" >"$TMPDIR_SMOKE/verify_tampered.json" \
    2>"$TMPDIR_SMOKE/verify_tampered.err"
  status=$?
  if [ "$status" -eq 1 ]; then
    pass "gm verify tampered proof"
  else
    fail "gm verify tampered proof"
  fi
else
  fail "gm verify tampered proof"
fi

# Leg 6: gm audit.
if "$GM" audit --session-file "$SESSION_FILE" --endpoint "$ENDPOINT" \
  >"$TMPDIR_SMOKE/audit.json" 2>"$TMPDIR_SMOKE/audit.err"; then
  pass "gm audit"
else
  fail "gm audit"
fi

# Leg 7: gm health against an unreachable endpoint -> exit 2.
"$GM" health --endpoint "$UNREACHABLE_ENDPOINT" \
  >"$TMPDIR_SMOKE/health_unreachable.json" 2>"$TMPDIR_SMOKE/health_unreachable.err"
status=$?
if [ "$status" -eq 2 ]; then
  pass "gm health unreachable"
else
  fail "gm health unreachable"
fi

# Leg 8: MCP legs against the live daemon.
if python3 "$SCRIPT_DIR/smoke_mcp.py" --gm-mcp "$GM_MCP" --endpoint "$ENDPOINT" --quiet \
  >"$TMPDIR_SMOKE/mcp_live.out" 2>"$TMPDIR_SMOKE/mcp_live.err"; then
  pass "mcp live"
else
  cat "$TMPDIR_SMOKE/mcp_live.err" >&2
  fail "mcp live"
fi

# Leg 9: MCP fail-closed legs against the unreachable endpoint.
if python3 "$SCRIPT_DIR/smoke_mcp.py" --gm-mcp "$GM_MCP" \
  --endpoint "$UNREACHABLE_ENDPOINT" --unreachable --quiet \
  >"$TMPDIR_SMOKE/mcp_unreachable.out" 2>"$TMPDIR_SMOKE/mcp_unreachable.err"; then
  pass "mcp fail-closed"
else
  cat "$TMPDIR_SMOKE/mcp_unreachable.err" >&2
  fail "mcp fail-closed"
fi

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
