#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_coverage_percent(path: Path) -> float:
    payload = json.loads(path.read_text(encoding="utf-8"))
    totals = payload.get("totals", {})
    if "percent_covered" in totals:
        return float(totals["percent_covered"])
    if "percent_covered_display" in totals:
        return float(totals["percent_covered_display"])
    raise ValueError(f"Could not find total coverage percentage in {path}")


def summarize_coverage(
    *,
    current_percent: float,
    previous_percent: float | None,
    baseline_label: str,
) -> list[str]:
    lines = [
        "## Coverage summary",
        f"- Current coverage: {current_percent:.2f}%",
    ]
    if previous_percent is None:
        lines.append("- Baseline coverage: unavailable")
        lines.append(
            "- Result: no previous successful baseline was available, so no drop check ran."
        )
        return lines

    delta = current_percent - previous_percent
    lines.append(f"- Baseline coverage ({baseline_label}): {previous_percent:.2f}%")
    if delta < 0:
        lines.append(f"- Result: coverage dropped by {abs(delta):.2f} percentage points.")
    elif delta > 0:
        lines.append(f"- Result: coverage improved by {delta:.2f} percentage points.")
    else:
        lines.append("- Result: coverage stayed flat.")
    return lines


def write_summary(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail when coverage drops against a prior baseline."
    )
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to the current coverage JSON.",
    )
    parser.add_argument("--previous", type=Path, help="Path to the previous coverage JSON.")
    parser.add_argument(
        "--baseline-label",
        default="previous successful run",
        help="Human-readable label for the previous baseline.",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Optional file to write a markdown summary into, such as $GITHUB_STEP_SUMMARY.",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.01,
        help="Allowed drop in coverage percentage points before failing.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    current_percent = load_coverage_percent(args.current)
    previous_percent = None
    if args.previous and args.previous.exists():
        previous_percent = load_coverage_percent(args.previous)

    lines = summarize_coverage(
        current_percent=current_percent,
        previous_percent=previous_percent,
        baseline_label=args.baseline_label,
    )
    print("\n".join(lines))
    if args.summary_file:
        write_summary(args.summary_file, lines)

    if previous_percent is None:
        return 0

    if current_percent + args.tolerance < previous_percent:
        print(
            f"Coverage dropped from {previous_percent:.2f}% to {current_percent:.2f}%.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
