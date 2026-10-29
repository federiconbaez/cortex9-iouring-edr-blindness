#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
make -C c
exec python3 -m edr_blindness.measure --runs "${RUNS:-30}" --out results "$@"
