"""Command-line interface for ``python -m oes32_membrane_shield``."""

from __future__ import annotations

import argparse

from .core import format_monte_carlo_report, run_monte_carlo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an OES-32 membrane shield simulation.")
    parser.add_argument(
        "--iterations", type=int, default=5000, help="Number of proposals to simulate."
    )
    parser.add_argument("--tau", type=float, default=0.08, help="Maximum residual before latching.")
    parser.add_argument(
        "--noise-scale", type=float, default=0.02, help="Gaussian proposal noise scale."
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="Optional deterministic proposal seed."
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    print(
        format_monte_carlo_report(
            run_monte_carlo(
                iterations=args.iterations,
                tau=args.tau,
                noise_scale=args.noise_scale,
                seed=args.seed,
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
