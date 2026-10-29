"""Minimal io_uring engine (ctypes). Benign local ops only."""

from __future__ import annotations

import ctypes
import ctypes.util
import mmap
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

SYS_io_uring_setup = 425
SYS_io_uring_enter = 426
IORING_OFF_SQ_RING = 0
IORING_OFF_CQ_RING = 0x8000000
IORING_OFF_SQES = 0x10000000
IORING_ENTER_GETEVENTS = 1
AT_FDCWD = -100
O_CREAT = 0x40
O_RDONLY = 0x0
O_RDWR = 0x2
O_TRUNC = 0x200
O_DIRECTORY = 0x10000
STATX_BASIC_STATS = 0x7FF


def _load_opcodes() -> dict[str, int]:
    hdr = Path("/usr/include/linux/io_uring.h")
    if not hdr.exists():
        # Fallback for CI images that ship the uapi header elsewhere.
        for cand in (
            Path("/usr/include/linux/io_uring.h"),
            Path("/usr/include/asm-generic/unistd.h"),
        ):
            if cand.exists():
                hdr = cand
                break
    text = hdr.read_text() if hdr.exists() else ""
    if "IORING_OP_NOP" not in text:
        # Hardcoded x86_64 Linux 6.x values (verified against 6.12 uapi).
        return {
            "IORING_OP_OPENAT": 18,
            "IORING_OP_CLOSE": 19,
            "IORING_OP_STATX": 21,
            "IORING_OP_READ": 22,
            "IORING_OP_WRITE": 23,
            "IORING_OP_RENAMEAT": 35,
            "IORING_OP_UNLINKAT": 36,
            "IORING_OP_MKDIRAT": 37,
        }
    start = text.index("IORING_OP_NOP")
    end = text.index("IORING_OP_LAST")
    block = text[start:end]
    val = 0
    ops: dict[str, int] = {}
    for tok in re.finditer(r"IORING_OP_[A-Z0-9_]+(?:\s*=\s*\d+)?", block):
        s = tok.group()
        if "=" in s:
            name, v = s.split("=")
            name = name.strip()
            val = int(v.strip())
        else:
            name = s.strip()
        ops[name] = val
        val += 1
    return ops


OP = _load_opcodes()


class _IoSqringOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32),
        ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32),
        ("ring_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("dropped", ctypes.c_uint32),
        ("array", ctypes.c_uint32),
        ("resv1", ctypes.c_uint32),
        ("user_addr", ctypes.c_uint64),
    ]


class _IoCqringOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32),
        ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32),
        ("ring_entries", ctypes.c_uint32),
        ("overflow", ctypes.c_uint32),
        ("cqes", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("resv1", ctypes.c_uint32),
        ("user_addr", ctypes.c_uint64),
    ]


class _Params(ctypes.Structure):
    _fields_ = [
        ("sq_entries", ctypes.c_uint32),
        ("cq_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("sq_thread_cpu", ctypes.c_uint32),
        ("sq_thread_idle", ctypes.c_uint32),
        ("features", ctypes.c_uint32),
        ("wq_fd", ctypes.c_uint32),
        ("resv", ctypes.c_uint32 * 3),
        ("sq_off", _IoSqringOffsets),
        ("cq_off", _IoCqringOffsets),
    ]


@dataclass
class Cqe:
    user_data: int
    res: int


class Uring:
    """Single-thread io_uring wrapper. Keeps path/data buffers alive across enter."""

    def __init__(self, entries: int = 32) -> None:
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._params = _Params()
        self._fd = self._libc.syscall(
            SYS_io_uring_setup, entries, ctypes.byref(self._params)
        )
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "io_uring_setup failed")
        self._sq = mmap.mmap(self._fd, 64 * 1024, offset=IORING_OFF_SQ_RING)
        self._cq = mmap.mmap(self._fd, 64 * 1024, offset=IORING_OFF_CQ_RING)
        self._sqes = mmap.mmap(
            self._fd, 64 * self._params.sq_entries, offset=IORING_OFF_SQES
        )
        self._keep: list[ctypes.Array] = []
        self._next_ud = 1

    def close(self) -> None:
        try:
            self._sqes.close()
            self._sq.close()
            self._cq.close()
        finally:
            os.close(self._fd)

    def __enter__(self) -> "Uring":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _buf(self, data: bytes) -> ctypes.Array:
        arr = (ctypes.c_char * len(data)).from_buffer_copy(data)
        self._keep.append(arr)
        return arr

    def _path_buf(self, path: Path | str) -> ctypes.Array:
        return self._buf(str(path).encode() + b"\x00")

    def _put(self, idx: int, blob: bytes) -> None:
        assert len(blob) == 64
        self._sqes[idx * 64 : (idx + 1) * 64] = blob

    def _sqe(self, opcode: int, fd: int = 0, off: int = 0, addr: int = 0,
             length: int = 0, op_flags: int = 0, user_data: int = 0,
             splice_fd_in: int = 0) -> bytes:
        b = bytearray(64)
        b[0] = opcode & 0xFF
        struct.pack_into("<i", b, 4, fd)
        struct.pack_into("<Q", b, 8, off & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<Q", b, 16, addr & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into("<I", b, 24, length & 0xFFFFFFFF)
        struct.pack_into("<I", b, 28, op_flags & 0xFFFFFFFF)
        struct.pack_into("<Q", b, 32, user_data & 0xFFFFFFFFFFFFFFFF)
        if splice_fd_in:
            struct.pack_into("<i", b, 40, splice_fd_in)  # not used for our ops
        return bytes(b)

    def submit(self, prepared: list[tuple[int, bytes]]) -> list[Cqe]:
        """prepared: list of (sqe_index, sqe_bytes). Submits all, waits for all CQEs."""
        for idx, blob in prepared:
            self._put(idx, blob)
        n = len(prepared)
        mask = struct.unpack_from("<I", self._sq, self._params.sq_off.ring_mask)[0]
        tail = struct.unpack_from("<I", self._sq, self._params.sq_off.tail)[0]
        for i, (idx, _) in enumerate(prepared):
            struct.pack_into(
                "<I",
                self._sq,
                self._params.sq_off.array + ((tail + i) & mask) * 4,
                idx,
            )
        struct.pack_into(
            "<I", self._sq, self._params.sq_off.tail, (tail + n) & 0xFFFFFFFF
        )
        ret = self._libc.syscall(
            SYS_io_uring_enter,
            self._fd,
            n,
            n,
            IORING_ENTER_GETEVENTS,
            None,
            0,
        )
        if ret != n:
            raise OSError(ctypes.get_errno(), f"io_uring_enter returned {ret}")
        out: list[Cqe] = []
        for _ in range(n):
            h = struct.unpack_from("<I", self._cq, self._params.cq_off.head)[0]
            t = struct.unpack_from("<I", self._cq, self._params.cq_off.tail)[0]
            if h == t:
                raise RuntimeError("missing CQE")
            cm = struct.unpack_from("<I", self._cq, self._params.cq_off.ring_mask)[0]
            off = self._params.cq_off.cqes + (h & cm) * 16
            user_data, res, _flags = struct.unpack_from("<QiI", self._cq, off)
            struct.pack_into(
                "<I", self._cq, self._params.cq_off.head, (h + 1) & 0xFFFFFFFF
            )
            out.append(Cqe(user_data=user_data, res=res))
        return out

    def peek_opcodes(self, indices: Iterable[int]) -> list[int]:
        """Read opcode byte from each SQE slot (Tracer C ring-peek)."""
        out = []
        for idx in indices:
            out.append(self._sqes[idx * 64])
        return out

    def ud(self) -> int:
        v = self._next_ud
        self._next_ud += 1
        return v

    # --- builders for the 8-op matrix ---

    def prep_openat(self, idx: int, path: Path, flags: int, mode: int = 0o644) -> tuple[int, bytes, int]:
        pb = self._path_buf(path)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_OPENAT"],
            fd=AT_FDCWD,
            addr=ctypes.addressof(pb),
            length=mode,
            op_flags=flags,
            user_data=ud,
        )
        return idx, blob, ud

    def prep_close(self, idx: int, fd: int) -> tuple[int, bytes, int]:
        ud = self.ud()
        return idx, self._sqe(OP["IORING_OP_CLOSE"], fd=fd, user_data=ud), ud

    def prep_read(self, idx: int, fd: int, length: int) -> tuple[int, bytes, int, ctypes.Array]:
        buf = (ctypes.c_char * length)()
        self._keep.append(buf)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_READ"],
            fd=fd,
            off=0,
            addr=ctypes.addressof(buf),
            length=length,
            user_data=ud,
        )
        return idx, blob, ud, buf

    def prep_write(self, idx: int, fd: int, data: bytes) -> tuple[int, bytes, int]:
        arr = self._buf(data)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_WRITE"],
            fd=fd,
            off=0,
            addr=ctypes.addressof(arr),
            length=len(data),
            user_data=ud,
        )
        return idx, blob, ud

    def prep_statx(self, idx: int, path: Path) -> tuple[int, bytes, int]:
        """STATX SQE (liburing 2.9 / Linux 6.12):

        addr=pathname, off/addr2=statxbuf, len=mask, statx_flags(op_flags)=AT_flags.
        """
        pb = self._path_buf(path)
        stx = (ctypes.c_char * 0x100)()
        self._keep.append(stx)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_STATX"],
            fd=AT_FDCWD,
            off=ctypes.addressof(stx),
            addr=ctypes.addressof(pb),
            length=STATX_BASIC_STATS,
            op_flags=0,
            user_data=ud,
        )
        return idx, blob, ud


    def prep_unlinkat(self, idx: int, path: Path) -> tuple[int, bytes, int]:
        pb = self._path_buf(path)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_UNLINKAT"],
            fd=AT_FDCWD,
            addr=ctypes.addressof(pb),
            op_flags=0,
            user_data=ud,
        )
        return idx, blob, ud

    def prep_renameat(self, idx: int, old: Path, new: Path) -> tuple[int, bytes, int]:
        # renameat: fd=olddirfd, addr=oldpath, len=newdirfd, addr2/off=newpath? 
        # liburing: sqe->fd = olddirfd; sqe->addr = oldpath; sqe->len = newdirfd;
        #           sqe->addr2 = newpath; sqe->rename_flags = flags
        ob = self._path_buf(old)
        nb = self._path_buf(new)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_RENAMEAT"],
            fd=AT_FDCWD,
            off=ctypes.addressof(nb),  # addr2 = newpath
            addr=ctypes.addressof(ob),
            length=AT_FDCWD & 0xFFFFFFFF,  # newdirfd as u32
            op_flags=0,
            user_data=ud,
        )
        return idx, blob, ud

    def prep_mkdirat(self, idx: int, path: Path, mode: int = 0o755) -> tuple[int, bytes, int]:
        pb = self._path_buf(path)
        ud = self.ud()
        blob = self._sqe(
            OP["IORING_OP_MKDIRAT"],
            fd=AT_FDCWD,
            addr=ctypes.addressof(pb),
            length=mode,
            user_data=ud,
        )
        return idx, blob, ud


# Opcode name by value for Tracer C attribution
OPCODE_NAME = {
    OP["IORING_OP_OPENAT"]: "openat",
    OP["IORING_OP_CLOSE"]: "close",
    OP["IORING_OP_READ"]: "read",
    OP["IORING_OP_WRITE"]: "write",
    OP["IORING_OP_STATX"]: "statx",
    OP["IORING_OP_UNLINKAT"]: "unlinkat",
    OP["IORING_OP_RENAMEAT"]: "renameat",
    OP["IORING_OP_MKDIRAT"]: "mkdirat",
}
