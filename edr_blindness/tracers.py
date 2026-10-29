"""Tracer A (syscall-only via strace) and Tracer C (io_uring-aware)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import OPS
from .uring import OP

REPO_ROOT = Path(__file__).resolve().parent.parent
VICTIM = REPO_ROOT / "c" / "victim"

SYSCALL_FOR_OP = {
    "openat": {"openat", "openat2", "open"},
    "read": {"read", "readv", "pread64", "preadv"},
    "write": {"write", "writev", "pwrite64", "pwritev"},
    "close": {"close", "close_range"},
    "statx": {"statx", "newfstatat", "fstatat64", "stat", "fstat", "lstat"},
    "unlinkat": {"unlinkat", "unlink"},
    "renameat": {"renameat", "renameat2", "rename"},
    "mkdirat": {"mkdirat", "mkdir"},
}

TRACE_A_FILTER = (
    "openat,openat2,open,read,readv,pread64,write,writev,pwrite64,"
    "close,close_range,statx,newfstatat,stat,fstat,lstat,"
    "unlinkat,unlink,renameat,renameat2,rename,mkdirat,mkdir"
)

OPCODE_FOR_OP = {
    "openat": OP["IORING_OP_OPENAT"],
    "read": OP["IORING_OP_READ"],
    "write": OP["IORING_OP_WRITE"],
    "close": OP["IORING_OP_CLOSE"],
    "statx": OP["IORING_OP_STATX"],
    "unlinkat": OP["IORING_OP_UNLINKAT"],
    "renameat": OP["IORING_OP_RENAMEAT"],
    "mkdirat": OP["IORING_OP_MKDIRAT"],
}


@dataclass
class TraceScore:
    tracer: str
    attributed: dict[str, bool]
    score: float
    raw: str = ""

    @property
    def attributed_count(self) -> int:
        return sum(1 for v in self.attributed.values() if v)


def ensure_victim() -> Path:
    if not VICTIM.exists():
        subprocess.run(["make", "-C", str(REPO_ROOT / "c")], check=True)
    if not VICTIM.exists():
        raise RuntimeError(f"victim binary missing at {VICTIM}")
    return VICTIM


_LINE_RE = re.compile(
    r"^(?:\d+\s+)?(?P<name>[a-z0-9_]+)\((?P<args>.*)\)\s*=\s*(?P<ret>.+)$"
)


def _score_strace_for_workdir(raw: str, workdir: str) -> TraceScore:
    """Attribute ops only when syscalls clearly touch workdir fds/paths.

    Path ops: workdir string appears in the strace line.
    read/write/close: fd was previously returned by an openat of a workdir path.
    """
    wd = str(workdir)
    fd_from_wd: set[int] = set()
    seen_ops: set[str] = set()

    for line in raw.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        name = m.group("name")
        args = m.group("args")
        ret = m.group("ret").strip()
        touches_wd = wd in args

        if name in {"openat", "openat2", "open"} and touches_wd:
            seen_ops.add("openat")
            # ret is the fd on success
            try:
                fd = int(ret.split()[0])
                if fd >= 0:
                    fd_from_wd.add(fd)
            except ValueError:
                pass
        elif name in {"statx", "newfstatat", "stat", "lstat", "fstat"} and touches_wd:
            seen_ops.add("statx")
        elif name in {"unlinkat", "unlink"} and touches_wd:
            seen_ops.add("unlinkat")
        elif name in {"renameat", "renameat2", "rename"} and touches_wd:
            seen_ops.add("renameat")
        elif name in {"mkdirat", "mkdir"} and touches_wd:
            seen_ops.add("mkdirat")
        elif name in {"read", "readv", "pread64", "preadv"}:
            fd_m = re.match(r"(\d+)", args)
            if fd_m and int(fd_m.group(1)) in fd_from_wd:
                seen_ops.add("read")
        elif name in {"write", "writev", "pwrite64", "pwritev"}:
            fd_m = re.match(r"(\d+)", args)
            if fd_m and int(fd_m.group(1)) in fd_from_wd:
                seen_ops.add("write")
        elif name in {"close", "close_range"}:
            fd_m = re.match(r"(\d+)", args)
            if fd_m and int(fd_m.group(1)) in fd_from_wd:
                seen_ops.add("close")
                fd_from_wd.discard(int(fd_m.group(1)))

    attributed = {op: (op in seen_ops) for op in OPS}
    n = sum(1 for v in attributed.values() if v)
    return TraceScore(tracer="A", attributed=attributed, score=n / len(OPS), raw=raw)


def _run_strace(mode: str, workdir: Path) -> tuple[str, str, int]:
    ensure_victim()
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "strace",
        "-f",
        "-e",
        f"trace={TRACE_A_FILTER}",
        "-o",
        "/dev/stderr",
        "--",
        str(VICTIM),
        str(workdir),
        mode,
    ]
    try:
        proc = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError as exc:
        raise RuntimeError("strace is required for Tracer A") from exc
    return proc.stdout or "", proc.stderr or "", proc.returncode


def run_tracer_a(workdir: Path) -> TraceScore:
    _out, err, rc = _run_strace("uring", workdir)
    if rc not in (0,):
        # still score whatever was traced; surface rc in raw
        pass
    score = _score_strace_for_workdir(err, str(workdir))
    score.raw = f"rc={rc}\n{err}"
    return score


def run_tracer_a_on_classic(workdir: Path) -> TraceScore:
    _out, err, rc = _run_strace("classic", workdir)
    score = _score_strace_for_workdir(err, str(workdir))
    score.raw = f"rc={rc}\n{err}"
    return score


def run_tracer_c_ringpeek(workdir: Path) -> TraceScore:
    """Tracer C: opcodes peeked from SQE at the submit site (userspace hook).

    The victim prints peeked opcodes as JSON on stdout. A perfect score is by
    construction of that hook; CI enforce.yml adds an independent ftrace check.
    """
    ensure_victim()
    workdir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(VICTIM), str(workdir), "uring"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"victim uring failed rc={proc.returncode}: {proc.stderr}"
        )
    line = (proc.stdout or "").strip().splitlines()[-1]
    data = json.loads(line)
    peeked = set(int(x) for x in data["peeked_opcodes"])
    attributed = {op: (OPCODE_FOR_OP[op] in peeked) for op in OPS}
    n = sum(1 for v in attributed.values() if v)
    return TraceScore(
        tracer="C-ringpeek",
        attributed=attributed,
        score=n / len(OPS),
        raw=line,
    )


def run_tracer_c_strace_enter(workdir: Path) -> TraceScore:
    ensure_victim()
    workdir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=io_uring_setup,io_uring_enter",
            "-o",
            "/dev/stderr",
            "--",
            str(VICTIM),
            str(workdir),
            "uring",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    raw = proc.stderr or ""
    enters = len(re.findall(r"io_uring_enter\(", raw))
    return TraceScore(
        tracer="C-enter",
        attributed={op: enters > 0 for op in OPS},
        score=1.0 if enters > 0 else 0.0,
        raw=f"enters={enters}\n{raw}",
    )


def run_tracer_c_ftrace(workdir: Path) -> TraceScore:
    """Kernel io_uring tracepoints. Requires root. Fails loudly if unavailable."""
    tracing = Path("/sys/kernel/tracing")
    if not os.access(tracing, os.R_OK):
        tracing = Path("/sys/kernel/debug/tracing")
    events_dir = tracing / "events" / "io_uring"
    if not events_dir.exists():
        raise RuntimeError(f"io_uring tracepoints unavailable at {events_dir}")

    candidates = ["io_uring_submit_req", "io_uring_complete", "io_uring_submit"]
    enabled: list[str] = []
    for name in candidates:
        ev = events_dir / name / "enable"
        if ev.exists():
            ev.write_text("1")
            enabled.append(name)
    if not enabled:
        raise RuntimeError(f"no usable io_uring tracepoint among {candidates}")

    (tracing / "trace").write_text("")
    try:
        ensure_victim()
        workdir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [str(VICTIM), str(workdir), "uring"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        data = (tracing / "trace").read_text(errors="replace")
    finally:
        for name in enabled:
            (events_dir / name / "enable").write_text("0")

    if proc.returncode != 0:
        raise RuntimeError(f"victim failed under ftrace rc={proc.returncode}")

    seen_opcodes: set[int] = set()
    for m in re.finditer(r"opcode[=:]?\s*(0x[0-9a-fA-F]+|\d+)", data):
        v = m.group(1)
        seen_opcodes.add(int(v, 16) if v.lower().startswith("0x") else int(v))

    attributed = {op: (OPCODE_FOR_OP[op] in seen_opcodes) for op in OPS}
    # Fallback: if trace has many lines but no parseable opcode, fail loudly
    if not seen_opcodes and len(data.strip()) < 10:
        raise RuntimeError(
            "ftrace enabled but produced no io_uring events; "
            "refusing to report a silent zero"
        )
    n = sum(1 for v in attributed.values() if v)
    return TraceScore(
        tracer="C-ftrace",
        attributed=attributed,
        score=n / len(OPS) if seen_opcodes else 0.0,
        raw=data[-4000:],
    )
