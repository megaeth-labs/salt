#!/usr/bin/env python3
"""Score and gate SALT mutation-testing runs.

Commands:
  exclude-re  --suppressions <toml>
      Print one --exclude-re argument pair per function-scoped suppression.

  report --results <mutants.out> [--suppressions <toml>]
      Score cargo-mutants output, apply line suppressions, write an optional
      Markdown report, and fail if unsuppressed survivors or timeouts remain.
      A missing results directory fails closed: scripts/mutation_test.sh always
      materializes a result set, even when there is nothing to mutate.

  orphans --suppressions <toml> --universe <file>
      Fail if any suppression no longer matches a live mutant.
"""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

MAX_SURVIVORS_SHOWN = 20
VALID_KINDS = {"function", "line"}
VALID_CATEGORIES = {"equivalent", "dead", "timeout"}


@dataclass(frozen=True)
class Suppression:
    kind: str
    category: str
    file: str
    justification: str
    reviewer: str
    mutant: str | None = None
    pattern: str | None = None
    line: int | None = None


def _required_string(entry: dict, field: str, idx: int, errors: list[str]) -> str | None:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"suppression #{idx}: missing `{field}`")
        return None
    return value.strip()


def load_suppressions(path: Path | None) -> tuple[list[Suppression], list[Suppression]]:
    """Return (function_scoped, line_scoped) suppressions."""
    if path is None:
        return [], []
    if not path.exists():
        raise ValueError(f"suppressions file not found: {path}")

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = data.get("suppress", [])
    if not isinstance(entries, list):
        raise ValueError("`suppress` must be an array of tables")

    errors: list[str] = []
    parsed: list[Suppression] = []
    for idx, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            errors.append(f"suppression #{idx}: entry must be a table")
            continue

        kind = _required_string(entry, "kind", idx, errors)
        category = _required_string(entry, "category", idx, errors)
        file = _required_string(entry, "file", idx, errors)
        justification = _required_string(entry, "justification", idx, errors)
        reviewer = _required_string(entry, "reviewer", idx, errors)

        if kind is not None and kind not in VALID_KINDS:
            errors.append(
                f"suppression #{idx}: kind must be one of {sorted(VALID_KINDS)}"
            )
        if category is not None and category not in VALID_CATEGORIES:
            errors.append(
                f"suppression #{idx}: category must be one of {sorted(VALID_CATEGORIES)}"
            )

        pattern = None
        mutant = None
        if kind == "function":
            pattern = _required_string(entry, "pattern", idx, errors)
        elif kind == "line":
            mutant = _required_string(entry, "mutant", idx, errors)

        if category == "timeout" and kind == "function":
            errors.append(
                f"suppression #{idx}: category `timeout` requires kind `line`; "
                "function suppressions exclude mutants from generation entirely"
            )

        line_no = entry.get("line")
        if line_no is not None:
            if kind != "line":
                errors.append(f"suppression #{idx}: `line` is only valid for kind `line`")
                line_no = None
            elif isinstance(line_no, bool) or not isinstance(line_no, int) or line_no <= 0:
                errors.append(f"suppression #{idx}: `line` must be a positive integer")
                line_no = None

        if all((kind, category, file, justification, reviewer)) and (
            (kind == "function" and pattern) or (kind == "line" and mutant)
        ):
            parsed.append(
                Suppression(
                    kind=kind,
                    category=category,
                    file=file,
                    justification=justification,
                    reviewer=reviewer,
                    mutant=mutant,
                    pattern=pattern,
                    line=line_no,
                )
            )

    if errors:
        raise ValueError("invalid suppressions:\n" + "\n".join(f"- {e}" for e in errors))

    function_scoped = [s for s in parsed if s.kind == "function"]
    line_scoped = [s for s in parsed if s.kind == "line"]
    return function_scoped, line_scoped


def read_lines(path: Path) -> list[str]:
    """Read non-empty stripped lines from a file if it exists."""
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


MUTANT_LOCATOR = re.compile(r"^(?P<file>[^\s:]+):(?P<line>\d+):\d+: (?P<body>.*)$")


def split_mutant(entry: str) -> tuple[str | None, int | None, str]:
    """Split a cargo-mutants result line into (file, line, body).

    Returns (None, None, entry) unchanged when the line carries no
    file:line:col locator, e.g. a locator-free suppression entry.
    """
    match = MUTANT_LOCATOR.match(entry)
    if match:
        return match.group("file"), int(match.group("line")), match.group("body")
    return None, None, entry


def write_report(report: str, comment: str | None, summary: str | None) -> None:
    """Write a report to requested output files and stdout."""
    if comment:
        Path(comment).write_text(report, encoding="utf-8")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report)
    print(report)


def cmd_exclude_re(args: argparse.Namespace) -> int:
    function_scoped, _ = load_suppressions(Path(args.suppressions))
    for entry in function_scoped:
        print("--exclude-re")
        print(entry.pattern)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    results = Path(args.results)
    if not results.exists():
        print(
            f"ERROR: no mutation results at {results}. scripts/mutation_test.sh "
            "records an explicit empty result set when there is nothing to "
            "mutate, so a missing directory means the mutation run misfired. "
            "Refusing to report a passing gate.",
            file=sys.stderr,
        )
        return 2

    for required in ("caught.txt", "missed.txt"):
        if not (results / required).exists():
            print(
                f"ERROR: {results / required} is missing although {results} exists. "
                "Refusing to report a passing gate on incomplete results.",
                file=sys.stderr,
            )
            return 2

    caught = read_lines(results / "caught.txt")
    missed = read_lines(results / "missed.txt")
    timeout = read_lines(results / "timeout.txt")
    unviable = read_lines(results / "unviable.txt")

    _, line_scoped = load_suppressions(Path(args.suppressions) if args.suppressions else None)

    # A line suppression only covers its own file (and its own line, when
    # pinned): identical mutant text can exist at several sites, and reviewing
    # one does not review the others. Categories are matched asymmetrically:
    # `equivalent`/`dead` prove the mutant cannot change observable behavior,
    # so they cover survivors and (flaky) timeouts alike; `timeout` only
    # proves non-termination, so it never excuses a mutant that ran to
    # completion and survived.
    def matchers(entries: list[Suppression]) -> tuple[set, set]:
        pinned: set[tuple[str, int, str]] = set()
        loose: set[tuple[str, str]] = set()
        for entry in entries:
            if not entry.mutant:
                continue
            body = split_mutant(entry.mutant)[2]
            if entry.line is not None:
                pinned.add((entry.file, entry.line, body))
            else:
                loose.add((entry.file, body))
        return pinned, loose

    behavior_pinned, behavior_loose = matchers(
        [entry for entry in line_scoped if entry.category != "timeout"]
    )
    timeout_pinned, timeout_loose = matchers(line_scoped)

    def partition(items: list[str], pinned: set, loose: set) -> tuple[list[str], list[str]]:
        suppressed: list[str] = []
        real: list[str] = []
        for item in items:
            file, line_no, body = split_mutant(item)
            if (file, body) in loose or (file, line_no, body) in pinned:
                suppressed.append(item)
            else:
                real.append(item)
        return suppressed, real

    suppressed_missed, real_survivors = partition(missed, behavior_pinned, behavior_loose)
    suppressed_timeouts, real_timeouts = partition(timeout, timeout_pinned, timeout_loose)

    viable = len(caught) + len(missed)
    scored = viable - len(suppressed_missed)
    killed = len(caught)
    score = (killed / scored * 100.0) if scored else 100.0
    gate_pass = not real_survivors and not real_timeouts

    if viable == 0 and not real_timeouts:
        report = (
            "## Mutation testing - PASS\n\n"
            "**Nothing to test**: no viable mutants were generated"
        )
        if unviable or timeout:
            report += f" ({len(unviable)} unviable, {len(timeout)} timed out)"
        report += ".\n"
        write_report(report, args.comment, args.summary)
        return 0

    status = "PASS" if gate_pass else "FAIL"
    lines = [
        f"## Mutation testing - {status}",
        "",
        f"**Mutation score: {score:.1f}%** ({killed}/{scored} viable mutants killed)",
        "",
        f"- caught: {len(caught)}",
        f"- survived, real gaps: {len(real_survivors)}",
        f"- timed out, inconclusive: {len(real_timeouts)}",
        f"- suppressed: {len(suppressed_missed) + len(suppressed_timeouts)}",
        f"- unviable: {len(unviable)}",
        f"- timeout total: {len(timeout)}",
        "",
    ]

    def append_section(title: str, blurb: str, items: list[str], artifact: str) -> None:
        lines.extend([f"### {title}", "", blurb, ""])
        for item in items[:MAX_SURVIVORS_SHOWN]:
            lines.append(f"- `{item}`")
        if len(items) > MAX_SURVIVORS_SHOWN:
            lines.append(
                f"- and {len(items) - MAX_SURVIVORS_SHOWN} more; see `{artifact}` in artifacts."
            )
        lines.append("")

    if real_survivors:
        append_section(
            "Survivors needing attention",
            "Each mutant changed code but no test failed. Add a killing test or record a justified suppression.",
            real_survivors,
            "missed.txt",
        )
    if real_timeouts:
        append_section(
            "Timed-out mutants",
            "Each timeout is inconclusive. Make it terminate, kill it, or record a justified suppression.",
            real_timeouts,
            "timeout.txt",
        )
    if not real_survivors and not real_timeouts:
        lines.append("No unsuppressed survivors or timeouts remain.")

    report = "\n".join(lines).rstrip() + "\n"
    write_report(report, args.comment, args.summary)
    return 0 if gate_pass else 1


def cmd_orphans(args: argparse.Namespace) -> int:
    function_scoped, line_scoped = load_suppressions(Path(args.suppressions))
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    universe = [ansi.sub("", line) for line in read_lines(Path(args.universe))]
    if not universe:
        print(f"ERROR: empty mutant universe at {args.universe}", file=sys.stderr)
        return 2

    universe_mutants = {split_mutant(line) for line in universe}
    universe_sites = {(file, body) for file, _, body in universe_mutants}
    bodies = {body for _, _, body in universe_mutants}

    orphans: list[str] = []
    for entry in function_scoped:
        try:
            regex = re.compile(entry.pattern or "")
        except re.error as err:
            print(f"bad regex in suppression {entry.file}: {err}", file=sys.stderr)
            return 2
        if not any(regex.search(body) for body in bodies):
            orphans.append(f"[function] {entry.file}: {entry.pattern}")

    for entry in line_scoped:
        if not entry.mutant:
            continue
        body = split_mutant(entry.mutant)[2]
        if entry.line is not None:
            if (entry.file, entry.line, body) not in universe_mutants:
                orphans.append(f"[line] {entry.file}:{entry.line}: {entry.mutant[:100]}")
        elif (entry.file, body) not in universe_sites:
            orphans.append(f"[line] {entry.file}: {entry.mutant[:100]}")

    total = len(function_scoped) + len(line_scoped)
    if orphans:
        print(f"{len(orphans)}/{total} suppressions are stale:")
        for orphan in orphans:
            print(f"  - {orphan}")
        return 1

    print(f"all {total} suppressions match a live mutant.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    exclude = sub.add_parser("exclude-re")
    exclude.add_argument("--suppressions", required=True)
    exclude.set_defaults(func=cmd_exclude_re)

    report = sub.add_parser("report")
    report.add_argument("--results", required=True)
    report.add_argument("--suppressions", default=None)
    report.add_argument("--comment", default=None)
    report.add_argument("--summary", default=None)
    report.set_defaults(func=cmd_report)

    orphans = sub.add_parser("orphans")
    orphans.add_argument("--suppressions", required=True)
    orphans.add_argument("--universe", required=True)
    orphans.set_defaults(func=cmd_orphans)

    args = parser.parse_args()
    try:
        return args.func(args)
    except ValueError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
