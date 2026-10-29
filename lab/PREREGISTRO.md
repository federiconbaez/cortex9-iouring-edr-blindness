# Pre-registro — cortex9-iouring-edr-blindness

Fecha de escritura (ART): 2026-10-29 ~15:25 ART. Este archivo se pushea **antes**
de correr la medición de 30 runs.

## Matriz (corpus fijado)

8 operaciones benignas sobre un directorio en tmpfs (`/dev/shm/...`):

1. `openat` — crear `a.txt`
2. `write` — escribir payload
3. `close`
4. `read` — releer `a.txt`
5. `statx` / `stat` (classic)
6. `mkdirat` / `mkdir`
7. `renameat` / `rename` — `b.txt` → `c.txt`
8. `unlinkat` / `unlink` — borrar `c.txt`

Cada op se ejecuta:

- vía **io_uring** (`IORING_OP_*`), victim C `c/victim`
- vía **syscalls clásicos** (baseline de sanidad para Tracer A)

Prohibido: rootkit, C2, red, modificar archivos fuera del workdir de medición.

## Trazadores

- **Tracer A (syscall-only):** `strace -f -e trace=<openat,read,write,close,statx/stat,unlink,rename,mkdir,...>`.
  Atribuye una op solo si el syscall correspondiente toca el workdir (path en
  args, o fd abierto previamente desde ese path). No observa `io_uring_enter`.
- **Tracer C (io_uring-aware):**
  - **ringpeek (local / CI userspace):** peeker lee `sqe->opcode` en el sitio de
    submit (modelo de agente userspace que engancha `io_uring_enter` y lee el
    SQ ring). Un score perfecto en este backend es **by construction** del
    punto de enganche; se declara como tal.
  - **ftrace (CI enforce, sudo):** `events/io_uring/*` — verificación independiente;
    falla fuerte si los tracepoints no cargan.

## Umbrales (aceptación)

Sobre **30 runs** independientes de la matriz io_uring:

| Métrica | Umbral |
|---|---|
| `mean(score_A)` | ≤ 0.25 |
| `mean(score_C)` con ringpeek | ≥ 0.9 |
| Ceguera de A | `p < 0.01` bajo H0 |

**H0 (pre-registrada):** Tracer A atribuye cada op io_uring con probabilidad
independiente `p = 0.5` (no hay ceguera estructural). Test: cola inferior
binomial exacta sobre `attributed_A_total` de `30 × 8 = 240` ensayos.
Rechazar H0 si `P(X ≤ attributed_A_total | n=240, p=0.5) < 0.01`.

Sanidad: Tracer A sobre la matriz **classic** debe dar `score_A ≥ 0.9` en una
corrida previa; si no, se aborta la medición (filtro strace roto).

## Qué no se mide aquí

- Falco + KRSI / Tetragon LSM (score_B del brief original): opcional, requiere
  stack de terceros; no instalado en la box ni en el runner por defecto.
- Overhead de CPU de un sensor in-kernel.
- Bypass de EDR en producción ajena.
