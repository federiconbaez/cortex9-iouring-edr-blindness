"""Unit / integration tests. A skipped test fails the job (no skips)."""

from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edr_blindness import OPS
from edr_blindness.matrix import run_classic_matrix, run_uring_matrix
from edr_blindness.tracers import (
    ensure_victim,
    run_tracer_a,
    run_tracer_a_on_classic,
    run_tracer_c_ringpeek,
    run_tracer_c_strace_enter,
)
from edr_blindness.measure import binom_sf


class TestUringMatrix(unittest.TestCase):
    def test_python_uring_matrix_all_ok(self) -> None:
        r = run_uring_matrix()
        self.assertEqual([o.name for o in r.ops], list(OPS))
        for o in r.ops:
            self.assertTrue(o.ok, msg=f"{o.name} failed: {o.detail}")

    def test_python_classic_matrix_all_ok(self) -> None:
        r = run_classic_matrix()
        self.assertEqual([o.name for o in r.ops], list(OPS))
        for o in r.ops:
            self.assertTrue(o.ok, msg=f"{o.name} failed: {o.detail}")


class TestTracers(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_victim()
        cls.root = Path("/dev/shm/cortex9-iouring-edr-blindness-tests")
        if cls.root.exists():
            shutil.rmtree(cls.root)
        cls.root.mkdir(parents=True)

    def test_tracer_a_sees_classic(self) -> None:
        s = run_tracer_a_on_classic(self.root / "classic")
        self.assertGreaterEqual(s.score, 0.9, msg=s.attributed)

    def test_tracer_a_blind_to_uring(self) -> None:
        s = run_tracer_a(self.root / "uring-a")
        self.assertLessEqual(s.score, 0.25, msg=s.attributed)

    def test_tracer_c_ringpeek(self) -> None:
        s = run_tracer_c_ringpeek(self.root / "uring-c")
        self.assertGreaterEqual(s.score, 0.9, msg=s.attributed)

    def test_tracer_c_sees_enter(self) -> None:
        s = run_tracer_c_strace_enter(self.root / "uring-e")
        self.assertEqual(s.score, 1.0, msg=s.raw[:200])


class TestStats(unittest.TestCase):
    def test_binom_sf_known(self) -> None:
        # P(X<=0 | n=10, p=0.5) = 1/1024
        self.assertAlmostEqual(binom_sf(0, 10, 0.5), 1 / 1024, places=12)
        # All attributed → p-value ~1
        self.assertGreater(binom_sf(240, 240, 0.5), 0.5)


if __name__ == "__main__":
    unittest.main()
