#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: export_benchmark_action_json.py <input.json> <time|throughput> <output.json>",
            file=sys.stderr,
        )
        return 1

    input_path = Path(sys.argv[1])
    metric = sys.argv[2]
    output_path = Path(sys.argv[3])

    payload = json.loads(input_path.read_text(encoding="utf-8"))
    entries = []

    for benchmark in payload.get("benchmarks", []):
        if metric == "time":
            value = benchmark.get("time_ns", benchmark.get("value"))
            if value is None:
                continue
            entries.append(
                {
                    "name": benchmark["name"],
                    "unit": "ms",
                    "value": value / 1_000_000,
                }
            )
            continue

        if metric == "throughput":
            throughput_value = benchmark.get("throughput_elem_per_sec", benchmark.get("throughput_value"))
            throughput_unit = "elem/s" if benchmark.get("throughput_elem_per_sec") is not None else benchmark.get("throughput_unit")
            if throughput_value is None or not throughput_unit:
                continue
            entries.append(
                {
                    "name": benchmark["name"],
                    "unit": throughput_unit,
                    "value": throughput_value,
                }
            )
            continue

        print(f"unsupported metric: {metric}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
