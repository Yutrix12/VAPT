"""Parse Trivy JSON vulnerability reports into simple Python objects."""

import argparse
import errno
import hashlib
import io
import json
import os
import reprlib
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn


SUPPORTED_SCHEMA_VERSION = 2
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# Personal data in repository scans: dropped as soon as the JSON is loaded.
GIT_PERSONAL_FIELDS = ("CommitMsg", "Author", "Committer")
MAX_SHOWN_FIXED_VERSIONS = 3
MAX_TARGET_WIDTH = 30


class ReportError(Exception):
    """A file cannot be used as a Trivy JSON report (bad input, not a bug)."""


@dataclass(frozen=True)
class Finding:
    """One vulnerability row: one vulnerability ID in one package."""

    fingerprint: str
    target: str
    vuln_class: str | None
    vuln_type: str | None
    vuln_id: str | None
    pkg_name: str | None
    installed_version: str | None
    fixed_version: str | None
    status: str
    severity: str
    title: str | None
    cvss_score: float | None
    primary_url: str | None
    published_date: str | None


@dataclass(frozen=True)
class Report:
    """One parsed report. Git author, committer and message are never kept."""

    file_name: str
    file_sha256: str
    schema_version: int | None
    trivy_version: str | None
    created_at: str | None
    artifact_name: str | None
    artifact_type: str | None
    os_family: str | None
    os_name: str | None
    repo_url: str | None
    branch: str | None
    commit: str | None
    misconfig_count: int
    secret_count: int
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class PackageGroup:
    """All findings for one installed package version in one target."""

    target: str
    pkg_name: str | None
    installed_version: str | None
    finding_count: int
    worst_severity: str
    fixed_versions: tuple[str, ...]
    has_unfixed: bool


# One parsed report together with its summary and package groups.
AnalysedReport = tuple[Report, dict[str, Any], list[PackageGroup]]
# What makes one package group: (target, package name, installed version).
GroupKey = tuple[str, str | None, str | None]


def group_key(item: Finding | PackageGroup) -> GroupKey:
    """The package group of a finding (or the key of a group itself)."""
    return (item.target, item.pkg_name, item.installed_version)


def is_result_list(items: Any) -> bool:
    """Return True if items is a list of result objects, each with a Target."""
    return isinstance(items, list) and all(
        isinstance(item, dict) and "Target" in item for item in items
    )


def to_report_dict(data: Any) -> dict[str, Any]:
    """Check parsed JSON is a Trivy report and return it with a Results list.

    New format: an object with SchemaVersion 2. Trivy leaves out Results
    when nothing was found, so a missing or null Results becomes an empty
    list. Old format: a non-empty list of result items, wrapped as
    {"Results": [...]} so later code handles one shape only.
    Raises ReportError with the reason if the data is neither.
    """
    if isinstance(data, dict):
        if "SchemaVersion" not in data:
            raise ReportError("not a Trivy JSON report (no SchemaVersion)")
        schema_version = data["SchemaVersion"]
        # The type check stops 2.0 (a float equal to 2) from passing.
        if not isinstance(schema_version, int) or (
            schema_version != SUPPORTED_SCHEMA_VERSION
        ):
            # reprlib.repr shortens a value from the file, so a huge value
            # still gives a short error line.
            raise ReportError(
                f"unsupported SchemaVersion {reprlib.repr(schema_version)} "
                f"(only {SUPPORTED_SCHEMA_VERSION} is supported)"
            )
        results = data.get("Results")
        if results is None:
            results = []
        if not is_result_list(results):
            raise ReportError(
                "not a Trivy JSON report "
                "(Results is not a list of result objects)"
            )
        return {**data, "Results": results}
    if isinstance(data, list) and data:
        if not is_result_list(data):
            raise ReportError(
                "not a Trivy JSON report (list items are not result objects)"
            )
        return {"Results": data}
    raise ReportError(
        "not a Trivy JSON report (expected an object or a list of results)"
    )


def drop_git_personal_data(data: Any) -> None:
    """Remove the git author, committer and commit message (rule l).

    Changes `data` in place. Called right after the JSON is parsed, before
    any other check, so nothing later can see or keep these fields.
    """
    if isinstance(data, dict):
        metadata = data.get("Metadata")
        if isinstance(metadata, dict):
            for key in GIT_PERSONAL_FIELDS:
                metadata.pop(key, None)


def reject_json_constant(name: str) -> NoReturn:
    """Reject NaN, Infinity and -Infinity, which are not valid JSON."""
    raise ReportError(f"not valid JSON ({name} is not allowed)")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a key that appears twice.

    By default json.loads keeps only the last duplicate, which would lose
    data without any error.
    """
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ReportError(
                f"not valid JSON (duplicate key {reprlib.repr(key)})"
            )
        obj[key] = value
    return obj


def check_file_name(file_name: str) -> None:
    """Accept only .json file names; ReportError otherwise."""
    if not file_name.lower().endswith(".json"):
        raise ReportError("only Trivy JSON reports are supported right now")


def read_report_file(path: Path) -> bytes:
    """Return the bytes of a file; ReportError if it cannot be read."""
    try:
        return path.read_bytes()
    except OSError as error:
        reason = error.strerror or type(error).__name__
        raise ReportError(f"cannot read file ({reason})") from error


def decode_report_json(raw: bytes) -> dict[str, Any]:
    """Parse raw file bytes as a Trivy JSON report and return it as a dict.

    Raises ReportError with a one-line reason for any bad input.
    """
    try:
        # Given bytes, json.loads detects UTF-8, UTF-8 with BOM, UTF-16 and
        # UTF-32 by itself (json.detect_encoding), so no manual decoding.
        data = json.loads(
            raw,
            parse_constant=reject_json_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as error:
        raise ReportError(
            "file is not UTF-8, UTF-16 or UTF-32 text"
        ) from error
    except json.JSONDecodeError as error:
        # Python's message for a control character already ends in " at"
        # ("Invalid control character at"); drop it so it is not doubled.
        message = error.msg.removesuffix(" at")
        raise ReportError(
            f"not valid JSON ({message} at line {error.lineno}, "
            f"column {error.colno})"
        ) from error
    except ValueError as error:
        # Other bad values, e.g. an integer longer than Python's digit limit.
        raise ReportError(f"not valid JSON ({error})") from error
    except RecursionError as error:
        raise ReportError("JSON is nested too deeply") from error
    drop_git_personal_data(data)
    return to_report_dict(data)


def get_text(item: dict[str, Any], key: str, where: str) -> str | None:
    """Return item[key] as text, or None if it is missing or empty.

    Raises ReportError if the value is not text or holds broken characters
    (lone surrogates) that would crash hashing or printing later.
    """
    value = item.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ReportError(f"{where}: {key} is not text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReportError(
            f"{where}: {key} contains invalid characters"
        ) from error
    return value


def get_list(item: dict[str, Any], key: str, where: str) -> list[Any]:
    """Return item[key] as a list; missing or null means an empty list."""
    value = item.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReportError(f"{where}: {key} is not a list")
    return value


def get_object(item: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    """Return item[key] as a dict; missing or null means an empty dict."""
    value = item.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ReportError(f"{where}: {key} is not an object")
    return value


def normalize_severity(value: Any) -> str:
    """Uppercase a known severity; anything else becomes UNKNOWN."""
    severity = value.upper() if isinstance(value, str) else ""
    return severity if severity in SEVERITIES else "UNKNOWN"


def highest_score(sources: list[Any], key: str, where: str) -> float | None:
    """Highest score under key (e.g. V3Score) across all CVSS sources."""
    scores = []
    for source in sources:
        if not isinstance(source, dict):
            raise ReportError(f"{where}: a CVSS entry is not an object")
        score = source.get(key)
        if score is None:
            continue
        # bool is a subclass of int in Python, so rule it out explicitly.
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ReportError(f"{where}: {key} is not a number")
        # CVSS scores run from 0 to 10. Checking before float() also stops
        # huge integers (OverflowError) and 1e400 (read as infinity).
        if not 0 <= score <= 10:
            raise ReportError(f"{where}: {key} is out of range 0-10")
        scores.append(float(score))
    return max(scores, default=None)


def best_cvss_score(vuln: dict[str, Any], where: str) -> float | None:
    """Highest V3Score across sources, else highest V2Score, else None."""
    sources = list(get_object(vuln, "CVSS", where).values())
    v3_score = highest_score(sources, "V3Score", where)
    if v3_score is not None:
        return v3_score
    return highest_score(sources, "V2Score", where)


def make_fingerprint(*parts: str | None) -> str:
    """sha256 of the parts joined by "|", first 16 hex chars; None is ""."""
    text = "|".join(part or "" for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def parse_finding(
    vuln: Any,
    target: str,
    vuln_class: str | None,
    vuln_type: str | None,
    where: str,
) -> Finding:
    """Turn one Vulnerabilities item into a Finding."""
    if not isinstance(vuln, dict):
        raise ReportError(f"{where}: not an object")
    vuln_id = get_text(vuln, "VulnerabilityID", where)
    pkg_name = get_text(vuln, "PkgName", where)
    return Finding(
        fingerprint=make_fingerprint(
            vuln_class, vuln_type, target, vuln_id, pkg_name
        ),
        target=target,
        vuln_class=vuln_class,
        vuln_type=vuln_type,
        vuln_id=vuln_id,
        pkg_name=pkg_name,
        installed_version=get_text(vuln, "InstalledVersion", where),
        fixed_version=get_text(vuln, "FixedVersion", where),
        status=get_text(vuln, "Status", where) or "unknown",
        severity=normalize_severity(vuln.get("Severity")),
        title=get_text(vuln, "Title", where),
        cvss_score=best_cvss_score(vuln, where),
        primary_url=get_text(vuln, "PrimaryURL", where),
        published_date=get_text(vuln, "PublishedDate", where),
    )


def parse_results(
    results: list[dict[str, Any]],
) -> tuple[list[Finding], int, int]:
    """Go through all results once.

    Returns the findings, the misconfiguration count and the secret count.
    """
    findings = []
    misconfig_count = 0
    secret_count = 0
    for result_number, result in enumerate(results, start=1):
        where = f"result {result_number}"
        target = get_text(result, "Target", where)
        if target is None:
            raise ReportError(f"{where}: Target is empty")
        vuln_class = get_text(result, "Class", where)
        vuln_type = get_text(result, "Type", where)
        vulns = get_list(result, "Vulnerabilities", where)
        for vuln_number, vuln in enumerate(vulns, start=1):
            findings.append(
                parse_finding(
                    vuln,
                    target,
                    vuln_class,
                    vuln_type,
                    f"{where}, vulnerability {vuln_number}",
                )
            )
        misconfig_count += len(get_list(result, "Misconfigurations", where))
        secret_count += len(get_list(result, "Secrets", where))
    return findings, misconfig_count, secret_count


def parse_report(path: Path) -> Report:
    """Read one Trivy JSON report file and return it as a Report.

    Raises ReportError with a one-line reason for any bad input.
    """
    # Check the name before reading, so a non-JSON file is never read.
    check_file_name(path.name)
    return parse_report_bytes(path.name, read_report_file(path))


def parse_report_bytes(file_name: str, raw: bytes) -> Report:
    """Parse the bytes of one Trivy JSON report (e.g. an uploaded file).

    Raises ReportError with a one-line reason for any bad input.
    """
    check_file_name(file_name)
    data = decode_report_json(raw)
    findings, misconfig_count, secret_count = parse_results(data["Results"])

    trivy_info = get_object(data, "Trivy", "report")
    metadata = get_object(data, "Metadata", "report")
    os_info = get_object(metadata, "OS", "report Metadata")
    artifact_type = get_text(data, "ArtifactType", "report")
    repo_url = branch = commit = None
    if artifact_type == "repository":
        # Only these three git fields are read: CommitMsg, Author and
        # Committer are personal data and must never be stored.
        repo_url = get_text(metadata, "RepoURL", "report Metadata")
        branch = get_text(metadata, "Branch", "report Metadata")
        commit = get_text(metadata, "Commit", "report Metadata")

    return Report(
        file_name=file_name,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        schema_version=data.get("SchemaVersion"),
        trivy_version=get_text(trivy_info, "Version", "report Trivy"),
        created_at=get_text(data, "CreatedAt", "report"),
        artifact_name=get_text(data, "ArtifactName", "report"),
        artifact_type=artifact_type,
        os_family=get_text(os_info, "Family", "report Metadata OS"),
        os_name=get_text(os_info, "Name", "report Metadata OS"),
        repo_url=repo_url,
        branch=branch,
        commit=commit,
        misconfig_count=misconfig_count,
        secret_count=secret_count,
        findings=tuple(findings),
    )


def summarize(report: Report) -> dict[str, Any]:
    """Count the findings of one report in a single pass.

    "unique_vuln_ids" counts every distinct vulnerability ID: CVE- and also
    GHSA-, DSA- or TEMP- IDs. A package is one (target, name, installed
    version), the same key the package groups use.
    """
    severity_counts = dict.fromkeys(SEVERITIES, 0)
    status_counts: Counter[str] = Counter()
    vuln_ids: set[str] = set()
    packages: set[GroupKey] = set()
    fingerprints: set[str] = set()
    without_fixed_version = 0
    for finding in report.findings:
        severity_counts[finding.severity] += 1
        status_counts[finding.status] += 1
        if finding.vuln_id is not None:
            vuln_ids.add(finding.vuln_id)
        if finding.pkg_name is not None:
            packages.add(group_key(finding))
        fingerprints.add(finding.fingerprint)
        if finding.fixed_version is None:
            without_fixed_version += 1
    return {
        "total": len(report.findings),
        "by_severity": severity_counts,
        "by_status": dict(status_counts.most_common()),
        "unique_vuln_ids": len(vuln_ids),
        "unique_packages": len(packages),
        "without_fixed_version": without_fixed_version,
        "distinct_fingerprints": len(fingerprints),
    }


def severity_rank(severity: str) -> int:
    """0 for CRITICAL up to 4 for UNKNOWN: a lower rank is more severe."""
    return SEVERITIES.index(severity)


def make_group(findings: list[Finding]) -> PackageGroup:
    """Build one PackageGroup from findings that share target and package."""
    first = findings[0]
    # Plain text sort of distinct values: versions are never compared as
    # versions (rule k), so "6.10" sorts before "6.9".
    fixed_versions = sorted(
        {f.fixed_version for f in findings if f.fixed_version is not None}
    )
    return PackageGroup(
        target=first.target,
        pkg_name=first.pkg_name,
        installed_version=first.installed_version,
        finding_count=len(findings),
        worst_severity=min((f.severity for f in findings), key=severity_rank),
        fixed_versions=tuple(fixed_versions),
        has_unfixed=any(f.fixed_version is None for f in findings),
    )


def group_sort_key(group: PackageGroup) -> tuple[int, int, str, str, str]:
    """Sort key: worst severity, then most findings, then names for ties."""
    return (
        severity_rank(group.worst_severity),
        -group.finding_count,
        group.target,
        group.pkg_name or "",
        group.installed_version or "",
    )


def findings_by_group(report: Report) -> dict[GroupKey, list[Finding]]:
    """The findings of each package group, in report order."""
    grouped: dict[GroupKey, list[Finding]] = {}
    for finding in report.findings:
        grouped.setdefault(group_key(finding), []).append(finding)
    return grouped


def group_by_package(report: Report) -> list[PackageGroup]:
    """Group findings by (target, package name, installed version).

    Sorted worst severity first, then by most findings. Ties are sorted by
    target, name and version so the order is always the same.
    """
    grouped = findings_by_group(report).values()
    groups = [make_group(findings) for findings in grouped]
    return sorted(groups, key=group_sort_key)


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
        ("Findings", str(summary["total"])),
        ("Severity", severities),
        ("Status", statuses or "-"),
        ("Unique", ", ".join([
            count_text(summary["unique_vuln_ids"], "vulnerability ID"),
            count_text(summary["unique_packages"], "package"),
            f"{summary['without_fixed_version']} without fixed version",
            count_text(summary["distinct_fingerprints"],
                       "distinct fingerprint"),
        ])),
        ("Also found", ", ".join([
            count_text(report.misconfig_count, "misconfiguration"),
            count_text(report.secret_count, "secret") + " (counted only)",
        ])),
    ]
    for label, value in lines:
        print(f"{label + ':':<12} {for_display(value)}")

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

    Example: `python trivy_parser.py ... | head -1`. Linux and macOS raise
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
