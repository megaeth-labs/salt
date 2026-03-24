#!/usr/bin/env python3
"""Render the PR perf regression report as a compact HTML summary."""

import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

THREAD_SUFFIX_RE = re.compile(r"^(?P<prefix>.+?)/(?P<count>\d+)\s+threads?$")


def load_json(path: Path) -> dict:
    """Load a JSON document from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def format_timestamp(value: str) -> str:
    """Format an ISO timestamp for display while preserving sentinel values."""
    if not value or value in {"unknown", "missing"}:
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_ns(value: float) -> str:
    """Render a time value in the most readable unit."""
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f} s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} ms"
    if value >= 1_000:
        return f"{value / 1_000:.2f} us"
    return f"{value:.2f} ns"


def format_pct(value: float) -> str:
    """Render a percentage delta with an explicit sign."""
    return f"{value:+.2f}%"


def format_count(value: float) -> str:
    """Render a throughput value using SI-style element units."""
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f} Gelem/s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} Melem/s"
    if value >= 1_000:
        return f"{value / 1_000:.2f} Kelem/s"
    return f"{value:.2f} elem/s"


def get_benchmark_time_ns(item: dict) -> float:
    """Read a benchmark's normalized time."""
    return float(item["time_ns"])


def get_benchmark_throughput(item: dict) -> float | None:
    """Read normalized throughput, falling back to the original parsed value."""
    normalized = item.get("throughput_elem_per_sec")
    if normalized is not None:
        return float(normalized)

    raw_value = item.get("throughput_value")
    return None if raw_value is None else float(raw_value)


def row_class(delta_pct: float, improvement_is_positive: bool) -> str:
    """Choose a semantic CSS class for a delta cell."""
    if delta_pct == 0:
        return ""
    is_improvement = delta_pct > 0 if improvement_is_positive else delta_pct < 0
    return "improvement" if is_improvement else "regression"


def benchmark_sort_key(name: str) -> tuple[str, int, str]:
    """Keep thread-count benchmarks grouped and ordered numerically.

    Criterion group names are typically emitted as `group/item`, so threaded
    runs look like `update 10000 KVs/1 threads`. Sorting by the raw string would
    place `16 threads` before `2 threads`, which makes comparisons harder to
    scan. This key keeps the common prefix together and sorts thread counts
    numerically in ascending order.
    """
    match = THREAD_SUFFIX_RE.match(name)
    if match:
        return (match.group("prefix"), int(match.group("count")), name)
    return (name, -1, name)


def render_rows(rows: list[dict]) -> str:
    """Render the comparison table body."""
    rendered = []
    for row in rows:
        baseline_throughput = "-"
        current_throughput = "-"
        throughput_delta = "-"
        time_delta_class = row_class(row["time_delta_pct"], improvement_is_positive=False)
        throughput_delta_class = ""
        if row["baseline_throughput"] is not None and row["current_throughput"] is not None:
            baseline_throughput = format_count(row["baseline_throughput"])
            current_throughput = format_count(row["current_throughput"])
            throughput_delta = format_pct(row["throughput_delta_pct"])
            throughput_delta_class = row_class(
                row["throughput_delta_pct"],
                improvement_is_positive=True,
            )
        rendered.append(
            "<tr>"
            f"<td class=\"bench-name\">{html.escape(row['name'])}</td>"
            f"<td class=\"num\">{html.escape(format_ns(row['baseline_time']))}</td>"
            f"<td class=\"num\">{html.escape(format_ns(row['current_time']))}</td>"
            f"<td class=\"num {time_delta_class}\">{html.escape(format_pct(row['time_delta_pct']))}</td>"
            f"<td class=\"num\">{html.escape(baseline_throughput)}</td>"
            f"<td class=\"num\">{html.escape(current_throughput)}</td>"
            f"<td class=\"num {throughput_delta_class}\">{html.escape(throughput_delta)}</td>"
            "</tr>"
        )
    return "\n".join(rendered)


def main() -> int:
    """Compare baseline and current benchmark JSON files and emit HTML + summary."""
    if len(sys.argv) != 4:
        print(
            "usage: render_pr_report.py <baseline.json> <current.json> <output-dir>",
            file=sys.stderr,
        )
        return 1

    baseline_path = Path(sys.argv[1])
    current_path = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])
    template_path = Path(__file__).with_name("report_template.html")

    baseline = load_json(baseline_path)
    current = load_json(current_path)

    baseline_map = {item["name"]: item for item in baseline.get("benchmarks", [])}
    current_map = {item["name"]: item for item in current.get("benchmarks", [])}
    names = sorted(set(baseline_map) & set(current_map), key=benchmark_sort_key)

    rows = []

    for name in names:
        baseline_value = get_benchmark_time_ns(baseline_map[name])
        current_value = get_benchmark_time_ns(current_map[name])
        delta_pct = ((current_value - baseline_value) / baseline_value * 100.0) if baseline_value else 0.0

        baseline_throughput_normalized = get_benchmark_throughput(baseline_map[name])
        current_throughput_normalized = get_benchmark_throughput(current_map[name])
        throughput_delta_pct = None
        if (
            baseline_throughput_normalized is not None
            and current_throughput_normalized is not None
            and baseline_throughput_normalized
        ):
            throughput_delta_pct = (
                (current_throughput_normalized - baseline_throughput_normalized)
                / baseline_throughput_normalized
                * 100.0
            )

        rows.append(
            {
                "name": name,
                "baseline_time": baseline_value,
                "current_time": current_value,
                "time_delta_pct": delta_pct,
                "baseline_throughput": baseline_throughput_normalized,
                "current_throughput": current_throughput_normalized,
                "throughput_delta_pct": throughput_delta_pct if throughput_delta_pct is not None else 0.0,
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    baseline_generated = format_timestamp(baseline.get("generated_at", "unknown"))
    current_generated = format_timestamp(current.get("generated_at", "unknown"))
    generated_at = datetime.now(timezone.utc).isoformat()
    rendered_generated_at = format_timestamp(generated_at)
    overlap_note = (
        "No overlapping benchmarks were found between the published main baseline and this PR run."
        if not rows
        else ""
    )

    template = template_path.read_text(encoding="utf-8")
    replacements = {
        "__GENERATED_AT__": rendered_generated_at,
        "__BASELINE_GENERATED_AT__": baseline_generated,
        "__CURRENT_GENERATED_AT__": current_generated,
        "__OVERLAP_NOTE__": html.escape(overlap_note),
        "__TABLE_ROWS__": render_rows(rows),
    }

    for key, value in replacements.items():
        template = template.replace(key, value)

    (output_dir / "index.html").write_text(template, encoding="utf-8")

    summary_lines = [
        "## Performance Benchmark Report",
        "",
        f"- Main baseline generated at: `{baseline_generated}`",
        f"- Current PR generated at: `{current_generated}`",
    ]
    if overlap_note:
        summary_lines.extend(["", overlap_note])

    (output_dir / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
