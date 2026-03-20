#!/usr/bin/env python3

import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def format_timestamp(value: str) -> str:
    if not value or value in {"unknown", "missing"}:
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_ns(value: float) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f} s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} ms"
    if value >= 1_000:
        return f"{value / 1_000:.2f} us"
    return f"{value:.2f} ns"


def format_pct(value: float) -> str:
    return f"{value:+.2f}%"


def format_count(value: float) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f} Gelem/s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} Melem/s"
    if value >= 1_000:
        return f"{value / 1_000:.2f} Kelem/s"
    return f"{value:.2f} elem/s"


def render_rows(rows: list[dict]) -> str:
    rendered = []
    for row in rows:
        time_status_class = row["time_status_class"]
        throughput_status_class = row["throughput_status_class"]
        baseline_throughput = "-"
        current_throughput = "-"
        throughput_delta = "-"
        if row["baseline_throughput"] is not None and row["current_throughput"] is not None:
            baseline_throughput = format_count(row["baseline_throughput"])
            current_throughput = format_count(row["current_throughput"])
            throughput_delta = format_pct(row["throughput_delta_pct"])
        rendered.append(
            "<tr>"
            f"<td>{html.escape(row['name'])}</td>"
            f"<td>{html.escape(format_ns(row['baseline_time']))}</td>"
            f"<td>{html.escape(format_ns(row['current_time']))}</td>"
            f"<td class=\"{time_status_class}\">{html.escape(format_pct(row['time_delta_pct']))}</td>"
            f"<td>{html.escape(baseline_throughput)}</td>"
            f"<td>{html.escape(current_throughput)}</td>"
            f"<td class=\"{throughput_status_class}\">{html.escape(throughput_delta)}</td>"
            "</tr>"
        )
    return "\n".join(rendered)


def main() -> int:
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
    names = sorted(set(baseline_map) & set(current_map))

    rows = []
    time_regression_count = 0
    time_improvement_count = 0
    throughput_regression_count = 0
    throughput_improvement_count = 0

    for name in names:
        baseline_value = float(baseline_map[name].get("time_ns", baseline_map[name]["value"]))
        current_value = float(current_map[name].get("time_ns", current_map[name]["value"]))
        delta_pct = ((current_value - baseline_value) / baseline_value * 100.0) if baseline_value else 0.0
        time_status_class = "regression" if delta_pct > 0 else "improvement"
        if delta_pct > 0:
            time_regression_count += 1
        elif delta_pct < 0:
            time_improvement_count += 1

        baseline_throughput = baseline_map[name].get("throughput_value")
        current_throughput = current_map[name].get("throughput_value")
        baseline_throughput_normalized = baseline_map[name].get("throughput_elem_per_sec")
        current_throughput_normalized = current_map[name].get("throughput_elem_per_sec")
        if baseline_throughput_normalized is None and baseline_throughput is not None:
            baseline_throughput_normalized = baseline_throughput
        if current_throughput_normalized is None and current_throughput is not None:
            current_throughput_normalized = current_throughput
        throughput_delta_pct = None
        throughput_status_class = ""
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
            throughput_status_class = "improvement" if throughput_delta_pct > 0 else "regression"
            if throughput_delta_pct > 0:
                throughput_improvement_count += 1
            elif throughput_delta_pct < 0:
                throughput_regression_count += 1

        rows.append(
            {
                "name": name,
                "baseline_time": baseline_value,
                "current_time": current_value,
                "time_delta_pct": delta_pct,
                "time_status_class": time_status_class,
                "baseline_throughput": baseline_throughput_normalized,
                "current_throughput": current_throughput_normalized,
                "throughput_delta_pct": throughput_delta_pct if throughput_delta_pct is not None else 0.0,
                "throughput_status_class": throughput_status_class,
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
        "__TIME_REGRESSION_COUNT__": str(time_regression_count),
        "__TIME_IMPROVEMENT_COUNT__": str(time_improvement_count),
        "__THROUGHPUT_REGRESSION_COUNT__": str(throughput_regression_count),
        "__THROUGHPUT_IMPROVEMENT_COUNT__": str(throughput_improvement_count),
        "__OVERLAP_NOTE__": html.escape(overlap_note),
        "__TABLE_ROWS__": render_rows(rows),
        "__CHART_ROWS_JSON__": json.dumps(rows),
    }

    for key, value in replacements.items():
        template = template.replace(key, value)

    (output_dir / "index.html").write_text(template, encoding="utf-8")

    summary_lines = [
        "## Performance Regression Report",
        "",
        f"- Main baseline generated at: `{baseline_generated}`",
        f"- Current PR generated at: `{current_generated}`",
        f"- Time regressions: `{time_regression_count}`",
        f"- Time improvements: `{time_improvement_count}`",
        f"- Throughput regressions: `{throughput_regression_count}`",
        f"- Throughput improvements: `{throughput_improvement_count}`",
    ]
    if overlap_note:
        summary_lines.extend(["", overlap_note])

    (output_dir / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
