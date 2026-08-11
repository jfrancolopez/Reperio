#!/usr/bin/env bash
# Expect a quality gate to reject its input (RPR-006).
#
# Proves a guardrail actually fails closed. Usage:
#   expect-gate-failure.sh "expected substring in output" -- <gate command...>
#
# Exits 0 only when the gate command fails and its output contains the expected
# substring. Exits 1 when the gate unexpectedly passes or the expected message
# is missing.

set -eu

expected="$1"
shift
if [ "${1:-}" = "--" ]; then
  shift
fi
if [ "$#" -eq 0 ]; then
  echo "expect-gate-failure.sh: no gate command given" >&2
  exit 2
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

set +e
"$@" >"$log" 2>&1
status=$?
set -e

cat "$log"

if [ "$status" -eq 0 ]; then
  echo "expect-gate-failure.sh: gate unexpectedly passed; expected rejection: $expected" >&2
  exit 1
fi

if ! grep -Fq "$expected" "$log"; then
  echo "expect-gate-failure.sh: gate failed but output lacks: $expected" >&2
  exit 1
fi

echo "expect-gate-failure.sh: gate rejected as expected: $expected"
