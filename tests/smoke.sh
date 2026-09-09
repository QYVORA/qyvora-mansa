#!/usr/bin/env bash
# Smoke test for the Mansa binary.
#
# Exercises the one-shot CLI and the interactive console in pipe mode,
# all under --sim (offline simulation) so no wireless hardware or
# authorization is required. Fails fast on the first broken command.
#
# Usage:
#   tests/smoke.sh [path-to-mansa-binary]    # default: builds into a temp dir
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-}"
if [ -z "$BIN" ]; then
    BIN="$(mktemp -d)/mansa"
    (cd "$ROOT" && GOFLAGS= go build -buildvcs=false -o "$BIN" ".")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export QYVORA_MANSA_SESSION_DIR="$WORK/sessions"
export QYVORA_MANSA_TARGET_STATE="$WORK/targets.json"

pass=0
fail=0

step() { printf '  %-55s' "$1"; }
ok() { pass=$((pass + 1)); printf ' ok\n'; }
bad() {
    fail=$((fail + 1))
    printf ' FAIL'
    [ -z "${2+x}" ] || printf ': %s' "$2"
    printf '\n'
}

json_valid() {
    python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null
}

# --- one-shot: version / help -------------------------------------------
step "version string"
if "$BIN" version 2>/dev/null | grep -q "mansa"; then ok; else bad "no version output"; fi

step "assess --sim -o json (23 APs, 57 findings)"
OUT="$("$BIN" assess --sim -o json 2>/dev/null)" \
    && echo "$OUT" | json_valid \
    && echo "$OUT" | grep -q '"findings"' \
    && echo "$OUT" | grep -q '"access_points"' \
    && ok || bad "assess json invalid or missing fields"

step "assess --sim risk fields present"
if echo "$OUT" | grep -Eq '"risk"|"score"|"level"'; then ok; else bad "no risk fields"; fi

step "analyze -o json (latest session)"
OUT="$("$BIN" analyze -o json 2>/dev/null)" \
    && echo "$OUT" | json_valid \
    && ok || bad "analyze json invalid"

step "capabilities -o json"
OUT="$("$BIN" capabilities -o json 2>/dev/null)" \
    && echo "$OUT" | json_valid \
    && ok || bad "capabilities json invalid"

step "report --format markdown --out"
RPT="$WORK/report.md"
"$BIN" report --format markdown --out "$RPT" >/dev/null 2>&1 \
    && [ -s "$RPT" ] && grep -qi "finding" "$RPT" && ok || bad "markdown report not written"

step "report --format json --out"
RPT="$WORK/report.json"
"$BIN" report --format json --out "$RPT" >/dev/null 2>&1 \
    && [ -s "$RPT" ] && python3 -c 'import json; json.load(open("'"$RPT"'"))' 2>/dev/null \
    && ok || bad "json report not written"

step "events JSONL (153 lines full sim)"
EV="$WORK/events.jsonl"
"$BIN" assess --sim --events "$EV" >/dev/null 2>&1 \
    && [ "$(wc -l < "$EV")" -eq 153 ] && ok || bad "expected 153 event lines, got $(wc -l < "$EV" 2>/dev/null)"

# --- interactive console in pipe mode ----
# The console is the bare invocation (no subcommand).
step "console pipe: sim on; status; scan; analyze; findings"
SCRIPT="sim on
status
scan
analyze
findings
exit"
echo "$SCRIPT" | "$BIN" > "$WORK/console.out" 2>&1 \
    && grep -q "backend:.*simulation" "$WORK/console.out" \
    && ok || bad "console pipe failed; tail:\n$(tail -20 "$WORK/console.out")"

step "console pipe: report --format markdown --out"
SCRIPT='report --format markdown --out '"$WORK"'/cp_report.md
exit'
echo "$SCRIPT" | "$BIN" > /dev/null 2>&1 \
    && [ -s "$WORK/cp_report.md" ] \
    && ok || bad "console report not written"

step "console pipe: status shows simulation"
SCRIPT="sim on
status
exit"
echo "$SCRIPT" | "$BIN" 2>&1 | grep -q "mode:.*simulation" \
    && ok || bad "status missing simulation context"

# --- error handling --------------------------------------------------------
step "unauthorized assess without --sim fails"
"$BIN" assess --interface wlan0 >/dev/null 2>&1 && bad "should have failed" || ok

printf '\nsmoke: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]