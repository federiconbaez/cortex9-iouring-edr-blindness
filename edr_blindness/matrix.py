"""8-op benign matrix on a tmpfs workdir, via io_uring and via plain syscalls."""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import OPS
from .uring import O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, Uring


@dataclass
class OpResult:
    name: str
    via: str  # "uring" | "classic"
    ok: bool
    detail: str = ""
    opcode: int | None = None


@dataclass
class MatrixResult:
    workdir: Path
    ops: list[OpResult] = field(default_factory=list)
    submitted_opcodes: list[int] = field(default_factory=list)

    @property
    def uring_ops(self) -> list[OpResult]:
        return [o for o in self.ops if o.via == "uring"]


def _fresh_workdir(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    # Prefer real tmpfs so the matrix matches the pre-registration.
    root = Path("/dev/shm") / "cortex9-iouring-edr-blindness"
    root.mkdir(parents=True, exist_ok=True)
    work = root / f"run-{os.getpid()}-{len(list(root.iterdir()))}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    return work


def run_uring_matrix(workdir: Path | None = None) -> MatrixResult:
    """Execute the 8 ops via io_uring. Returns per-op results + submitted opcodes."""
    work = workdir or _fresh_workdir(Path("."))
    file_a = work / "a.txt"
    file_b = work / "b.txt"
    file_c = work / "c-renamed.txt"
    dir_d = work / "d-dir"
    results = MatrixResult(workdir=work)

    with Uring(entries=32) as ring:
        prepared: list[tuple[int, bytes]] = []
        meta: list[str] = []  # op names in submission order
        extras: dict[str, object] = {}

        # 1 openat (create a.txt)
        idx, blob, _ud = ring.prep_openat(0, file_a, O_CREAT | O_RDWR | O_TRUNC, 0o644)
        prepared.append((idx, blob))
        meta.append("openat")
        results.submitted_opcodes.append(blob[0])

        cqes = ring.submit(prepared)
        prepared.clear()
        open_res = cqes[0].res
        op_ok = open_res >= 0
        results.ops.append(
            OpResult("openat", "uring", op_ok, detail=f"fd={open_res}", opcode=blob[0])
        )
        if not op_ok:
            return results
        fd = open_res

        # 2 write
        idx, blob, _ud = ring.prep_write(1, fd, b"payload-uring\n")
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult("write", "uring", cq.res == len(b"payload-uring\n"), detail=f"res={cq.res}", opcode=blob[0])
        )

        # 3 close
        idx, blob, _ud = ring.prep_close(2, fd)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult("close", "uring", cq.res == 0, detail=f"res={cq.res}", opcode=blob[0])
        )

        # 4 openat read-only + 5 read
        idx, blob, _ud = ring.prep_openat(3, file_a, O_RDONLY)
        results.submitted_opcodes.append(blob[0])
        # We already counted openat once; this second openat is scaffolding for read.
        # The matrix's "openat" slot is the first one. Extra open is not scored.
        rfd = ring.submit([(idx, blob)])[0].res
        if rfd < 0:
            results.ops.append(OpResult("read", "uring", False, detail=f"reopen={rfd}"))
            return results

        idx, blob, _ud, buf = ring.prep_read(4, rfd, 64)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult(
                "read",
                "uring",
                cq.res > 0,
                detail=f"res={cq.res}",
                opcode=blob[0],
            )
        )
        cidx, cblob, _ = ring.prep_close(5, rfd)
        ring.submit([(cidx, cblob)])  # drain; not scored

        # 6 statx
        idx, blob, _ud = ring.prep_statx(6, file_a)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult("statx", "uring", cq.res == 0, detail=f"res={cq.res}", opcode=blob[0])
        )

        # 7 mkdirat
        idx, blob, _ud = ring.prep_mkdirat(7, dir_d, 0o755)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult("mkdirat", "uring", cq.res == 0 and dir_d.is_dir(), detail=f"res={cq.res}", opcode=blob[0])
        )

        # seed file_b for rename
        file_b.write_text("rename-me\n")

        # 8 renameat
        idx, blob, _ud = ring.prep_renameat(8, file_b, file_c)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult(
                "renameat",
                "uring",
                cq.res == 0 and file_c.exists() and not file_b.exists(),
                detail=f"res={cq.res}",
                opcode=blob[0],
            )
        )

        # 9 unlinkat (score slot: unlinkat) — remove file_c
        idx, blob, _ud = ring.prep_unlinkat(9, file_c)
        results.submitted_opcodes.append(blob[0])
        cq = ring.submit([(idx, blob)])[0]
        results.ops.append(
            OpResult(
                "unlinkat",
                "uring",
                cq.res == 0 and not file_c.exists(),
                detail=f"res={cq.res}",
                opcode=blob[0],
            )
        )

    # Keep only the 8 scored ops in order of OPS
    by_name = {o.name: o for o in results.ops if o.name in OPS}
    results.ops = [by_name[n] for n in OPS if n in by_name]
    return results


def run_classic_matrix(workdir: Path | None = None) -> MatrixResult:
    """Same 8 ops via plain syscalls (baseline that Tracer A must see)."""
    work = workdir or _fresh_workdir(Path("."))
    file_a = work / "classic-a.txt"
    file_b = work / "classic-b.txt"
    file_c = work / "classic-c.txt"
    dir_d = work / "classic-d"
    results = MatrixResult(workdir=work)

    fd = os.open(file_a, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o644)
    results.ops.append(OpResult("openat", "classic", fd >= 0, detail=f"fd={fd}"))
    n = os.write(fd, b"payload-classic\n")
    results.ops.append(OpResult("write", "classic", n > 0, detail=f"n={n}"))
    os.close(fd)
    results.ops.append(OpResult("close", "classic", True))

    fd = os.open(file_a, os.O_RDONLY)
    data = os.read(fd, 64)
    results.ops.append(OpResult("read", "classic", len(data) > 0, detail=f"n={len(data)}"))
    os.close(fd)

    st = os.stat(file_a)
    results.ops.append(OpResult("statx", "classic", stat.S_ISREG(st.st_mode), detail=f"size={st.st_size}"))

    os.mkdir(dir_d, 0o755)
    results.ops.append(OpResult("mkdirat", "classic", dir_d.is_dir()))

    file_b.write_text("rename-me\n")
    os.rename(file_b, file_c)
    results.ops.append(OpResult("renameat", "classic", file_c.exists() and not file_b.exists()))

    os.unlink(file_c)
    results.ops.append(OpResult("unlinkat", "classic", not file_c.exists()))

    by_name = {o.name: o for o in results.ops}
    results.ops = [by_name[n] for n in OPS]
    return results
