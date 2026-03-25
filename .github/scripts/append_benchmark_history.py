#!/usr/bin/env python3
"""Append one benchmark run to the gh-pages history JSON.

Usage:
    append_benchmark_history.py <latest-main.json> <data.json> <commit> <date>

- latest-main.json : output of parse_cargo_bench.py
- data.json        : accumulated history file (created if absent)
- commit           : short commit SHA (7 chars)
- date             : commit date (YYYY-MM-DD)

The script extracts per-thread throughput (Kelem/s) by matching benchmark names
against thread-count patterns such as "1 thread", "2 threads", "4 threads", etc.
Up to MAX_ITEMS entries are kept; oldest entries are dropped first.
"""

import json
import re
import sys
from pathlib import Path

MAX_ITEMS = 30

THREAD_SLOTS = [1, 2, 4, 8, 16]
THREAD_KEY = {n: f"t{n}" for n in THREAD_SLOTS}


def extract_thread_count(name: str) -> int | None:
    """Return the thread count embedded in a benchmark name, or None."""
    m = re.search(r"(\d+)\s+threads?", name, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def throughput_kelem_per_sec(benchmark: dict) -> float | None:
    """Return throughput in Kelem/s from a parsed benchmark entry."""
    elems = benchmark.get("throughput_elem_per_sec")
    if elems is not None:
        return elems / 1_000.0

    value = benchmark.get("throughput_value")
    unit = benchmark.get("throughput_unit", "")
    if value is None:
        return None

    unit_scale = {
        "elem/s":   1.0 / 1_000.0,
        "Kelem/s":  1.0,
        "Melem/s":  1_000.0,
        "Gelem/s":  1_000_000.0,
    }
    scale = unit_scale.get(unit)
    return value * scale if scale is not None else None


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: append_benchmark_history.py <latest-main.json> <data.json> <commit> <date>",
            file=sys.stderr,
        )
        return 1

    latest_path = Path(sys.argv[1])
    history_path = Path(sys.argv[2])
    commit = sys.argv[3]
    date = sys.argv[4]

    parsed = json.loads(latest_path.read_text(encoding="utf-8"))

    throughput: dict[str, float] = {}
    for bench in parsed.get("benchmarks", []):
        threads = extract_thread_count(bench.get("name", ""))
        if threads is None or threads not in THREAD_SLOTS:
            continue
        kelem = throughput_kelem_per_sec(bench)
        if kelem is not None:
            throughput[THREAD_KEY[threads]] = round(kelem, 2)

    if not throughput:
        print(
            "warning: no per-thread throughput values found in latest-main.json",
            file=sys.stderr,
        )

    entry: dict = {"commit": commit, "date": date}
    entry.update(throughput)

    history = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    history.append(entry)

    if len(history) > MAX_ITEMS:
        history = history[-MAX_ITEMS:]

    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    print(f"History updated: {len(history)} entries in {history_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
