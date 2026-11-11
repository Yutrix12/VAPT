"""Command line: print the summary of one or more Trivy JSON reports."""

import argparse
import errno
import io
import json
import os
import reprlib
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from app.analysis.grouping import group_by_package
from app.analysis.summary import summarize
from app.parsers.json.parser import parse_report
from app.parsers.models import PackageGroup, Report, ReportError


MAX_SHOWN_FIXED_VERSIONS = 3
MAX_TARGET_WIDTH = 30


# One parsed report together with its summary and package groups.
AnalysedReport = tuple[Report, dict[str, Any], list[PackageGroup]]


def positive_int(text: str) -> int:
    """argparse type for --limit: a whole number of 1 or more."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{reprlib.repr(text)} is not a whole number"
        ) from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    """Describe the command line options."""
    parser = argparse.ArgumentParser(
        description="Summarize Trivy JSON vulnerability reports."
    )
    parser.add_argument(
        "files", nargs="+", type=Path, metavar="FILE",
        help="Trivy JSON report file(s)",
    )
    parser.add_argument(
        "--limit", type=positive_int, default=10, metavar="N",
        help="number of package groups to show per report (default: 10)",
    )
    parser.add_argument(
        "--json", type=Path, dest="json_out", metavar="OUT.json",
        help="also write all parsed data to this JSON file",
    )
    return parser


def for_display(text: str) -> str:
    """Escape characters that could control the terminal, e.g. ESC or newline.

    Reports can come from anyone, so a crafted value must not be able to
    recolour the screen or fake table rows. Shows them as \\x1b, \\n, ...
    """
    if text.isprintable():
        return text
    return "".join(
        char if char.isprintable()
        else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def count_text(count: int, singular: str, plural: str | None = None) -> str:
    """'1 package' or '2 packages'; plural defaults to singular + 's'."""
    word = singular if count == 1 else plural or singular + "s"
    return f"{count} {word}"


def format_scan_date(created_at: str | None) -> str:
    """Show the scan time as 'YYYY-MM-DD HH:MM:SS +HHMM'."""
    if created_at is None:
        return "unknown"
    try:
        moment = datetime.fromisoformat(created_at)
    except ValueError:
        # Not an ISO 8601 date: show the text exactly as Trivy wrote it.
        return created_at
    return moment.strftime("%Y-%m-%d %H:%M:%S %z").rstrip()


def format_fixed_versions(versions: tuple[str, ...]) -> str:
    """Show the first few fixed versions and how many more there are."""
    if not versions:
        return "-"
    shown = ", ".join(versions[:MAX_SHOWN_FIXED_VERSIONS])
    hidden = len(versions) - MAX_SHOWN_FIXED_VERSIONS
    return f"{shown} (+{hidden} more)" if hidden > 0 else shown


def format_target(target: str) -> str:
    """Show a target, keeping only its end (the file name) if it is long."""
    # Escape first, so the cut text is never wider than MAX_TARGET_WIDTH.
    text = for_display(target)
    if len(text) <= MAX_TARGET_WIDTH:
        return text
    return "..." + text[-(MAX_TARGET_WIDTH - 3):]


def format_table(header: list[str], rows: list[list[str]]) -> list[str]:
    """Lay out rows as text columns, each as wide as its longest cell."""
    columns = zip(header, *rows)
    widths = [max(len(cell) for cell in column) for column in columns]
    divider = ["-" * width for width in widths]
    lines = []
    for row in [header, divider, *rows]:
        cells = [cell.ljust(width) for cell, width in zip(row, widths)]
        lines.append("  ".join(cells).rstrip())
    return lines


def print_report(
    report: Report,
    summary: dict[str, Any],
    groups: list[PackageGroup],
    limit: int,
) -> None:
    """Print one report: details, summary and the top package groups.

    Every value from the file goes through for_display before printing.
    """
    lines = [
        ("File", report.file_name),
        ("Artifact", f"{report.artifact_name or 'unknown'} "
                     f"({report.artifact_type or 'unknown type'})"),
        ("Trivy", report.trivy_version or "unknown"),
        ("Scanned", format_scan_date(report.created_at)),
    ]
    git_details = [report.repo_url, report.branch, report.commit]
    if report.artifact_type == "repository" and not any(git_details):
        lines.append(("Repository", "no git details in report"))
    elif report.artifact_type == "repository":
        lines += [
            ("Repository", report.repo_url or "unknown"),
            ("Branch", report.branch or "unknown"),
            ("Commit", report.commit or "unknown"),
        ]
    else:
        os_text = " ".join(filter(None, [report.os_family, report.os_name]))
        lines.append(("OS", os_text or "unknown"))
    severities = ", ".join(
        f"{name} {count}" for name, count in summary["by_severity"].items()
    )
    statuses = ", ".join(
        f"{name} {count}" for name, count in summary["by_status"].items()
    )
    lines += [
        ("Vulnerabilities", str(summary["total"])),
        ("Severity", severities),
        ("Status", statuses or "-"),
        ("Unique", ", ".join([
            count_text(summary["unique_vuln_ids"], "vulnerability ID"),
            count_text(summary["unique_packages"], "package"),
            f"{summary['without_fixed_version']} without fixed version",
            count_text(summary["distinct_fingerprints"],
                       "distinct fingerprint"),
        ])),
        ("Other kinds", ", ".join([
            count_text(summary["by_kind"]["misconfiguration"], "misconfiguration")
            + f" ({count_text(summary['misconfig_passed'], 'passed check')}"
            + f", {count_text(summary['misconfig_exceptions'], 'exception')})",
            count_text(summary["by_kind"]["secret"], "secret"),
            count_text(summary["by_kind"]["license"], "license"),
        ])),
    ]
    for label, value in lines:
        print(f"{label + ':':<17} {for_display(value)}")

    if not groups:
        print("No vulnerable packages.")
        return
    shown = groups[:limit]
    print(f"\nTop {len(shown)} of "
          f"{count_text(len(groups), 'package group')}:")
    rows = [
        [
            format_target(group.target),
            for_display(group.pkg_name or "unknown"),
            for_display(group.installed_version or "unknown"),
            str(group.finding_count),
            group.worst_severity,
            for_display(format_fixed_versions(group.fixed_versions)),
        ]
        for group in shown
    ]
    header = [
        "Target", "Package", "Installed", "Findings", "Worst",
        "Fixed versions",
    ]
    for line in format_table(header, rows):
        print(f"  {line}")


def to_json_entry(analysed: AnalysedReport) -> dict[str, Any]:
    """One report, its summary and its package groups as plain JSON data."""
    report, summary, groups = analysed
    return {
        "report": asdict(report),
        "summary": summary,
        "package_groups": [asdict(group) for group in groups],
    }


def write_json(path: Path, reports: list[AnalysedReport]) -> None:
    """Write all parsed reports to one UTF-8 JSON file."""
    entries = [to_json_entry(analysed) for analysed in reports]
    text = json.dumps({"reports": entries}, indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")


def save_json(path: Path, reports: list[AnalysedReport]) -> bool:
    """Write the reports for --json and say what happened; False on failure."""
    shown_path = for_display(str(path))
    if not reports:
        # Do not replace OUT.json with an empty report list.
        print(f"Not writing {shown_path}: no report was parsed",
              file=sys.stderr)
        return False
    try:
        write_json(path, reports)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        print(f"Could not write {shown_path}: {reason}", file=sys.stderr)
        return False
    print(f"Wrote {count_text(len(reports), 'report')} to {shown_path}")
    return True


def is_input_file(json_out: Path, files: list[Path]) -> bool:
    """True if OUT.json is one of the input files, which it would overwrite.

    samefile asks the operating system, so different spellings, case on
    case-insensitive disks, links and hard links are all recognised. A
    file that does not exist yet cannot be an input.
    """
    if not json_out.exists():
        return False
    return any(path.exists() and json_out.samefile(path) for path in files)


def main(argv: list[str] | None = None) -> int:
    """Run the command line; return 0 on success, 1 if anything failed."""
    if isinstance(sys.stdout, io.TextIOWrapper):
        # Print characters the console cannot show as \uXXXX instead of
        # crashing (Windows consoles often use cp1252).
        sys.stdout.reconfigure(errors="backslashreplace")
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.json_out is not None:
        try:
            clash = is_input_file(args.json_out, args.files)
        except OSError as error:
            parser.error(f"cannot check the --json path "
                         f"({for_display(str(error))})")
        if clash:
            parser.error("--json OUT.json must not be one of the input files")

    had_problem = False
    analysed: list[AnalysedReport] = []
    for path in args.files:
        try:
            report = parse_report(path)
        except ReportError as error:
            print(
                f"Skipped {for_display(path.name)}: {for_display(str(error))}",
                file=sys.stderr,
            )
            had_problem = True
            continue
        analysed.append((report, summarize(report), group_by_package(report)))

    # Write the JSON before printing, so a closed output pipe
    # (e.g. "| head -1") cannot stop the file from being written.
    if args.json_out is not None and not save_json(args.json_out, analysed):
        had_problem = True

    for report, summary, groups in analysed:
        print_report(report, summary, groups, args.limit)
        print()
    return 1 if had_problem else 0


def is_closed_pipe(error: OSError) -> bool:
    """True if printing failed because the reader of our output went away.

    Example: `python cli.py ... | head -1`. Linux and macOS raise
    BrokenPipeError; Windows raises OSError EINVAL instead. main() catches
    every other OSError itself, so one reaching here comes from stdout.
    """
    return isinstance(error, BrokenPipeError) or error.errno == errno.EINVAL


if __name__ == "__main__":
    try:
        exit_code = main()
        # Flush inside the try so a closed pipe is caught here too.
        # stdout is None when there is no console at all (pythonw).
        if sys.stdout is not None:
            sys.stdout.flush()
    except OSError as error:
        if not is_closed_pipe(error):
            raise
        # As the Python docs advise ("Note on SIGPIPE"): send the rest of
        # stdout to devnull so the flush at shutdown does not fail again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        exit_code = 1
    sys.exit(exit_code)
