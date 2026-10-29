"""Measurement: 30 runs, score_A / score_C, binomial test for A's blindness."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import statistics
import time
from dataclasses import asdict
from pathlib import Path

from . import OPS
from .tracers import (
    run_tracer_a,
    run_tracer_a_on_classic,
    run_tracer_c_ringpeek,
    run_tracer_c_strace_enter,
)


def binom_sf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X~Binom(n,p). Exact sum, n<=240."""
    # Use log-space for stability
    # sf for lower tail
    total = 0.0
    for i in range(0, k + 1):
        # C(n,i) * p^i * (1-p)^(n-i)
        log_c = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
        log_pmf = log_c + i * math.log(p) + (n - i) * math.log(1 - p)
        total += math.exp(log_pmf)
    return total


def run_measurement(runs: int, out: Path, seed_tag: str) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    root = Path("/dev/shm/cortex9-iouring-edr-blindness") / f"measure-{seed_tag}"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    # Sanity: Tracer A must see classic syscalls
    classic_dir = root / "classic-sanity"
    classic_dir.mkdir()
    classic = run_tracer_a_on_classic(classic_dir)
    if classic.score < 0.9:
        raise RuntimeError(
            f"Tracer A sanity failed on classic syscalls: score={classic.score} "
            f"attributed={classic.attributed}. strace filter is broken."
        )

    scores_a: list[float] = []
    scores_c: list[float] = []
    scores_c_enter: list[float] = []
    attributed_a_total = 0
    attributed_c_total = 0
    per_run = []

    for i in range(runs):
        wd_a = root / f"a-{i}"
        wd_c = root / f"c-{i}"
        wd_a.mkdir()
        wd_c.mkdir()
        a = run_tracer_a(wd_a)
        c = run_tracer_c_ringpeek(wd_c)
        c_enter = run_tracer_c_strace_enter(root / f"e-{i}")
        scores_a.append(a.score)
        scores_c.append(c.score)
        scores_c_enter.append(c_enter.score)
        attributed_a_total += a.attributed_count
        attributed_c_total += c.attributed_count
        per_run.append(
            {
                "run": i,
                "score_A": a.score,
                "score_C": c.score,
                "score_C_enter": c_enter.score,
                "attributed_A": a.attributed,
                "attributed_C": c.attributed,
                "enters_raw_head": (c_enter.raw or "")[:200],
            }
        )

    n_ops = runs * len(OPS)
    # Pre-registered H0: Tracer A attributes each io_uring op with p=0.5
    # (no structural blindness). Alternative: p < 0.5.
    p_value = binom_sf(attributed_a_total, n_ops, 0.5)

    mean_a = statistics.mean(scores_a)
    mean_c = statistics.mean(scores_c)

    thresholds = {
        "score_A_max": 0.25,
        "score_C_min": 0.9,
        "p_value_max": 0.01,
        "runs": runs,
        "H0": "each io_uring op attributed by Tracer A with p=0.5",
    }
    pass_a = mean_a <= thresholds["score_A_max"]
    pass_c = mean_c >= thresholds["score_C_min"]
    pass_p = p_value < thresholds["p_value_max"]
    overall = pass_a and pass_c and pass_p

    report = {
        "seed_tag": seed_tag,
        "runs": runs,
        "ops_per_run": len(OPS),
        "ops": list(OPS),
        "thresholds": thresholds,
        "classic_sanity_score_A": classic.score,
        "classic_sanity_attributed": classic.attributed,
        "mean_score_A": mean_a,
        "mean_score_C": mean_c,
        "mean_score_C_enter": statistics.mean(scores_c_enter),
        "min_score_A": min(scores_a),
        "max_score_A": max(scores_a),
        "min_score_C": min(scores_c),
        "max_score_C": max(scores_c),
        "attributed_A_total": attributed_a_total,
        "attributed_C_total": attributed_c_total,
        "n_ops_total": n_ops,
        "p_value_A_blindness": p_value,
        "pass_score_A": pass_a,
        "pass_score_C": pass_c,
        "pass_p_value": pass_p,
        "overall_pass": overall,
        "tracer_C_note": (
            "score_C is ring-peek (userspace hook on SQE.opcode). "
            "A perfect score is by construction of that hook point; "
            "CI enforce.yml re-checks with io_uring tracepoints under sudo."
        ),
        "per_run": per_run,
    }
    out_path = out / f"measure-{seed_tag}.json"
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = out / f"measure-{seed_tag}.txt"
    lines = [
        f"runs={runs}",
        f"mean_score_A={mean_a:.4f} (threshold <= {thresholds['score_A_max']}) {'OK' if pass_a else 'NO CUMPLE'}",
        f"mean_score_C={mean_c:.4f} (threshold >= {thresholds['score_C_min']}) {'OK' if pass_c else 'NO CUMPLE'}",
        f"p_value={p_value:.6g} (threshold < {thresholds['p_value_max']}) {'OK' if pass_p else 'NO CUMPLE'}",
        f"attributed_A={attributed_a_total}/{n_ops}",
        f"attributed_C={attributed_c_total}/{n_ops}",
        f"classic_sanity_A={classic.score:.4f}",
        f"overall={'PASS' if overall else 'FAIL'}",
    ]
    summary.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--out", type=Path, default=Path("results"))
    ap.add_argument(
        "--tag",
        default=time.strftime("%Y%m%d-%H%M%S"),
        help="label for this measurement (no backdating of results files)",
    )
    args = ap.parse_args(argv)
    report = run_measurement(args.runs, args.out, args.tag)
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
