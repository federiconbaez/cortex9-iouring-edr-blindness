"""Harness: measure EDR blindness to io_uring file ops (benign, local only)."""

__version__ = "0.1.0"

OPS = (
    "openat",
    "read",
    "write",
    "close",
    "statx",
    "unlinkat",
    "renameat",
    "mkdirat",
)
