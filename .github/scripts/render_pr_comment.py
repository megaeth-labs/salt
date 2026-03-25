#!/usr/bin/env python3
"""Render the PR perf regression report as GitHub-friendly Markdown."""

import json
import re
import sys
from pathlib import Path

THREAD_SUFFIX_RE = re.compile(r"^(?P<prefix>.+?)/(?P<count>\d+)\s+threads?$")


def load_json(path: Path) -> dict:
    """Load a JSON document from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def format_pct(value: float) -> str:
    """Render a percentage delta with an explicit sign."""
    return f"{value:+.2f}%"


def get_benchmark_throughput(item: dict) -> float | None:
    """Read normalized throughput, falling back to the original parsed value."""
    normalized = item.get("throughput_elem_per_sec")
    if normalized is not None:
        return float(normalized)

    raw_value = item.get("throughput_value")
    return None if raw_value is None else float(raw_value)


def benchmark_sort_key(name: str) -> tuple[str, int, str]:
    """Keep thread-count benchmarks grouped and ordered numerically."""
    match = THREAD_SUFFIX_RE.match(name)
    if match:
        return (match.group("prefix"), int(match.group("count")), name)
    return (name, -1, name)


def build_rows(baseline: dict, current: dict) -> list[dict]:
    """Build comparable row objects from the baseline/current benchmark payloads."""
    baseline_map = {item["name"]: item for item in baseline.get("benchmarks", [])}
    current_map = {item["name"]: item for item in current.get("benchmarks", [])}
    names = sorted(set(baseline_map) & set(current_map), key=benchmark_sort_key)

    rows = []
    for name in names:
        baseline_throughput = get_benchmark_throughput(baseline_map[name])
        current_throughput = get_benchmark_throughput(current_map[name])
        throughput_delta_pct = None
        if baseline_throughput is not None and current_throughput is not None and baseline_throughput:
            throughput_delta_pct = ((current_throughput - baseline_throughput) / baseline_throughput) * 100.0

        rows.append(
            {
                "name": name,
                "baseline_throughput": baseline_throughput,
                "current_throughput": current_throughput,
                "throughput_delta_pct": throughput_delta_pct,
            }
        )

    return rows


def summarize_rows(rows: list[dict]) -> list[str]:
    """Build a short summary for the comment header."""
    if not rows:
        return ["This PR run did not match any benchmark entries from the latest `main` baseline."]
    return [f"Compared `{len(rows)}` benchmark(s) against the latest `main` baseline."]


def render_table(rows: list[dict]) -> str:
    """Render a Markdown table for the detailed comparison section."""
    if not rows:
        return "_No overlapping benchmarks found._"

    lines = [
        "| Benchmark | Baseline (Kelem/s) | PR (Kelem/s) | Change |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        baseline_throughput = "-"
        current_throughput = "-"
        throughput_delta = "-"
        if row["baseline_throughput"] is not None and row["current_throughput"] is not None:
            baseline_throughput = f"{row['baseline_throughput'] / 1_000:.2f}"
            current_throughput = f"{row['current_throughput'] / 1_000:.2f}"
            throughput_delta = format_pct(row["throughput_delta_pct"])

        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{row['name']}`",
                    f"`{baseline_throughput}`" if baseline_throughput != "-" else "-",
                    f"`{current_throughput}`" if current_throughput != "-" else "-",
                    f"`{throughput_delta}`" if throughput_delta != "-" else "-",
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def render_comment(rows: list[dict]) -> str:
    """Render the full Markdown PR comment body."""
    sections = [
        "## Performance Benchmark Comparison",
        "",
        *summarize_rows(rows),
        "",
        "<details open>",
        "<summary><strong>Detailed Comparison</strong></summary>",
        "",
        render_table(rows),
        "",
        "</details>",
        "",
    ]
    return "\n".join(sections)


def main() -> int:
    """Compare baseline and current benchmark JSON files and emit Markdown files."""
    if len(sys.argv) != 4:
        print(
            "usage: render_pr_comment.py <baseline.json> <current.json> <output-dir>",
            file=sys.stderr,
        )
        return 1

    baseline_path = Path(sys.argv[1])
    current_path = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])

    baseline = load_json(baseline_path)
    current = load_json(current_path)
    rows = build_rows(baseline, current)

    output_dir.mkdir(parents=True, exist_ok=True)

    comment = render_comment(rows)
    summary_lines = [
        "## Performance Benchmark Comparison",
        "",
        *summarize_rows(rows),
    ]

    (output_dir / "comment.md").write_text(comment, encoding="utf-8")
    (output_dir / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
