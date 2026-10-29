#!/usr/bin/env bash
# Tracer C via io_uring tracepoints. Must run as root. Fails loudly — no skips.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
make -C c

# Ensure tracefs/debugfs are mounted (GitHub runners often need this).
if [[ ! -d /sys/kernel/tracing/events ]]; then
  mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
fi
if [[ ! -d /sys/kernel/debug/tracing/events ]] && [[ -d /sys/kernel/debug ]]; then
  mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
fi

TRACING=""
for cand in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  if [[ -d "$cand/events/io_uring" ]]; then
    TRACING="$cand"
    break
  fi
done
if [[ -z "$TRACING" ]]; then
  echo "FAIL: io_uring tracepoints not available" >&2
  exit 1
fi

ENABLED=()
for ev in io_uring_submit_req io_uring_complete io_uring_submit; do
  if [[ -f "$TRACING/events/io_uring/$ev/enable" ]]; then
    echo 1 > "$TRACING/events/io_uring/$ev/enable"
    ENABLED+=("$ev")
  fi
done
if [[ ${#ENABLED[@]} -eq 0 ]]; then
  echo "FAIL: no usable io_uring tracepoint enabled" >&2
  exit 1
fi
echo "enabled: ${ENABLED[*]}"

echo > "$TRACING/trace"
WD="$(mktemp -d /dev/shm/c9-uring-enforce.XXXXXX)"
cleanup() {
  for ev in "${ENABLED[@]}"; do
    echo 0 > "$TRACING/events/io_uring/$ev/enable" || true
  done
  rm -rf "$WD"
}
trap cleanup EXIT

./c/victim "$WD" uring >/tmp/c9-uring-out.json
TRACE="$(cat "$TRACING/trace")"
if [[ -z "${TRACE// }" ]]; then
  echo "FAIL: tracepoints enabled but trace is empty" >&2
  exit 1
fi
echo "$TRACE" | tail -n 30
# Require at least one opcode-looking token OR a known event name in the trace
if ! echo "$TRACE" | grep -Eq 'io_uring_|opcode'; then
  echo "FAIL: trace lacks io_uring markers" >&2
  exit 1
fi
echo "enforce ftrace: OK (${#TRACE} bytes of trace)"
