# cortex9-iouring-edr-blindness

Harness that scores whether a **syscall-only** monitor is blind to benign
file operations submitted through **io_uring**, and whether an
**io_uring-aware** tracer recovers them.

No rootkit. No C2. No network. Eight local ops on tmpfs (`/dev/shm`).

## Why

ARMO's *Curing* write-up (Apr 2025) shows that tools which only watch classic
syscalls miss work done through `io_uring`
([blog](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/),
paragraphs read on 2026-10-29). Falco documented the same gap and points to the
KRSI plugin from 0.40
([GHSA-7cq5-h4p2-h37p](https://github.com/falcosecurity/falco/security/advisories/GHSA-7cq5-h4p2-h37p),
read on 2026-10-29). Operators still lack a small, reproducible self-test that
answers: *does my stack see these ops when they go through io_uring?*

This repo is that self-test for two tracers you can run without a third-party
EDR:

| Tracer | What it sees | How |
|---|---|---|
| **A** | classic file syscalls only | `strace` filtered to openat/read/write/close/stat*/unlink/rename/mkdir, attributed only when the syscall touches the measurement workdir |
| **C** | `io_uring` submissions | (1) ring-peek of `sqe->opcode` at the submit site; (2) in CI, kernel `io_uring` tracepoints under sudo |

## Pre-registration

Thresholds and H0 were fixed in [`lab/PREREGISTRO.md`](lab/PREREGISTRO.md)
**before** the 30-run measurement (commit on `main` that adds that file).

- `mean(score_A) ≤ 0.25`
- `mean(score_C) ≥ 0.9` (ringpeek)
- A's blindness significant at `p < 0.01` under H0: each io_uring op is
  attributed by Tracer A independently with probability 0.5 (exact lower-tail
  binomial on `30 × 8 = 240` trials)

## Reproduce

```bash
sudo apt-get install -y build-essential liburing-dev strace
./scripts/run_tests.sh
./scripts/measure.sh                  # 30 runs → results/
# optional, needs root + tracefs:
sudo ./scripts/enforce_ftrace.sh
```

## Measured (box, 2026-10-29)

Host: Linux 6.12.94, unprivileged user, `/dev/shm` tmpfs.
Command: `python3 -m edr_blindness.measure --runs 30 --out results --tag box-20261029`

| Métrica | Valor | Umbral | ¿Cumple? |
|---|---|---|---|
| `mean(score_A)` | **0.0000** (0/240 ops) | ≤ 0.25 | sí |
| `mean(score_C)` ringpeek | **1.0000** (240/240) | ≥ 0.9 | sí |
| `p` (ceguera de A) | **5.66×10⁻⁷³** | < 0.01 | sí |
| sanidad A sobre classic | **1.0000** | ≥ 0.9 | sí |

Raw: [`results/measure-box-20261029.json`](results/measure-box-20261029.json),
[`results/measure-box-20261029.txt`](results/measure-box-20261029.txt).

`score_C = 1.0` on the ringpeek backend is **by construction** of the hook
point (the peeker reads `sqe->opcode` next to submit). The independent check is
`enforce.yml`, which enables `events/io_uring/*` under sudo and fails the job if
tracepoints are missing or silent.

## Scope / not verified

- **Not measured:** Falco+KRSI / Tetragon LSM (`score_B` in the original brief).
  Those stacks are not installed here; the harness stops at A and C.
- **Not a rootkit detector.** The victim only does benign local file ops. It
  does not reimplement Curing and does not fetch the Curing PoC repo.
- **Ringpeek ≠ production EDR.** It models "an agent that hooks io_uring and
  reads the SQ ring", not a specific vendor product.
- **Box limits:** `unprivileged_bpf_disabled=2`; no unprivileged BPF load.
  Kernel tracepoints need the enforce job (sudo).
- SQE layouts were taken from `/usr/include/linux/io_uring.h` and
  `/usr/include/liburing.h` on the build host (liburing 2.9).

## License

Apache-2.0. See [LICENSE](LICENSE).
