"""Turn Trivy's text (table) output into a Report (same structure as JSON).

The table carries less than a JSON report: no Trivy version, scan date,
artifact, OS or git data, no class, no CVSS score, no published date, a title
cut by Trivy, and no fix text for misconfigurations. What it lacks is named in
`NOT_IN_TEXT` (shown as "not in this format"), never guessed. The source lines
Trivy prints around a secret or a misconfiguration are never read: they can
hold the secret itself (secrets rule). Facts: trivy-formats skill.
"""

import hashlib
import re
from dataclasses import dataclass, field
from json import detect_encoding

from app.parsers.common import normalize_severity
from app.parsers.models import (
    Finding,
    License,
    Misconfiguration,
    Report,
    ReportError,
    Secret,
)
from app.parsers.text.tables import Row, read_table

TRIVY_TEXT = "Trivy text (table)"
# Fields the text format does not carry (names the page knows).
NOT_IN_TEXT = (
    "schema_version", "trivy_version", "created_at", "artifact_name", "artifact_type", "os", "git",
    "class", "cvss_score", "published_date", "full_titles", "misconfiguration_title", "resolution", "link",
    "confidence",
)

VULN_HEADER = ["Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title"]
LICENSE_HEADER = ["Package", "License", "Classification", "Severity"]
SEVERITY = "UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL"
# The bracket of a heading names a class (not a type) for these results.
CLASS_WORDS = ("secrets", "license", "license-file")

HEADING_RULE = re.compile(r"^={3,}$")
TOTAL = re.compile(r"^Total: (\d+) \(UNKNOWN: (\d+), LOW: (\d+), MEDIUM: (\d+), HIGH: (\d+), CRITICAL: (\d+)\)$")
TESTS = re.compile(r"^Tests: \d+ \(SUCCESSES: (\d+), FAILURES: (\d+)\)$")
FAILURES = re.compile(r"^Failures: (\d+) \(UNKNOWN: (\d+), LOW: (\d+), MEDIUM: (\d+), HIGH: (\d+), CRITICAL: (\d+)\)$")
MISCONFIG_HEAD = re.compile(rf"^(\S+) \(({SEVERITY})\): ?(.*)$")
SECRET_HEAD = re.compile(rf"^({SEVERITY}): (.*) \(([^()]*)\)$")  # SEVERITY: Category (rule-id)
# The second layout (no IDs): "HIGH: message" and "CRITICAL (AWS): title".
MISCONFIG_HEAD_PLAIN = re.compile(rf"^({SEVERITY}): ?(.*)$")
SECRET_HEAD_BRACKET = re.compile(rf"^({SEVERITY}) \(([^()]*)\): ?(.*)$")
SUMMARY_COUNTS = ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses")
AVD_HOST = "avd.aquasec.com"
LOCATION = re.compile(r"^\s*.+?:(\d+)(?:-(\d+))?(?: \(offset: \d+ bytes\))?\s*$")
HEADING_BRACKET = re.compile(r"^(.*\S) \(([^()\s]+)\)$")
LIBRARY_FILE = re.compile(r"^(.*\S) \([^()\s]+\)$")
SEVERITY_ORDER = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


# One row of the Report Summary: target, type (None for "-") and the four counts.
SummaryEntry = tuple[str, str | None, list[int]]


@dataclass
class Parsed:
    findings: list[Finding] = field(default_factory=list)
    misconfigurations: list[Misconfiguration] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    licenses: list[License] = field(default_factory=list)
    misconfig_passed: int = 0
    missing: set[str] = field(default_factory=set)  # fields this layout lacks, on top of NOT_IN_TEXT


@dataclass
class Heading:
    target: str
    result_type: str | None
    class_word: str | None


def decode_text(raw: bytes) -> str | None:
    """The bytes as text (UTF-8, with BOM, UTF-16 or UTF-32), or None."""
    try:
        text = raw.decode(detect_encoding(raw))
    except (UnicodeDecodeError, LookupError):
        return None
    if "\x00" in text:
        return None
    return text.lstrip("﻿")


def is_rule(lines: list[str], index: int, char: str) -> bool:
    """True if lines[index] is a line made only of `char` (a border or divider)."""
    return index < len(lines) and len(lines[index].strip()) >= 10 and set(lines[index].strip()) == {char}


def next_content(lines: list[str], index: int) -> int:
    """The index of the first non-blank line from `index` on (len(lines) if none)."""
    while index < len(lines) and not lines[index].strip():
        index += 1
    return index


def heading_at(lines: list[str], index: int) -> bool:
    """A result heading: a text line, a line of "=" (3 or more), then a Total or
    Tests line. The last part keeps a "====" line inside a description or in
    printed source from being taken for a heading."""
    if not (
        index + 1 < len(lines)
        and bool(lines[index].strip())
        and not HEADING_RULE.match(lines[index].strip())
        and bool(HEADING_RULE.match(lines[index + 1].strip()))
    ):
        return False
    first = next_content(lines, index + 2)
    return first < len(lines) and lines[first].startswith(("Total: ", "Tests: "))


def starts_secret_block(line: str) -> bool:
    """True if the line looks like the first line of a secret block (either layout)."""
    return bool(SECRET_HEAD.match(line.strip()) or SECRET_HEAD_BRACKET.match(line.strip()))


def is_trivy_text(text: str) -> bool:
    """True if the text looks like Trivy's table output (a summary or a result section)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "Report Summary":
            after = next_content(lines, index + 1)
            if after < len(lines) and lines[after].startswith("┌"):
                return True
        if heading_at(lines, index):
            first = next_content(lines, index + 2)
            if first >= len(lines):
                continue
            if lines[first].startswith("Tests: "):
                return True
            if lines[first].startswith("Total: "):
                after = next_content(lines, first + 1)
                if after < len(lines) and (
                    lines[after].startswith("┌")
                    or (starts_secret_block(lines[after]) and is_rule(lines, after + 1, "═"))
                ):
                    return True
    return False


def parse_report_text(file_name: str, raw: bytes, text: str) -> Report:
    """Build a Report from the text of a Trivy table output.

    `raw` is only used for the file's sha256. Raises ReportError with a
    one-line reason for any broken table or any count that does not match.
    """
    lines = text.splitlines()
    summary, first_section = read_summary(lines)
    parsed = Parsed()
    starts = [i for i in range(first_section, len(lines)) if heading_at(lines, i)]
    for number, start in enumerate(starts):
        end = starts[number + 1] if number + 1 < len(starts) else len(lines)
        parse_section(lines, start, end, summary, parsed)
    check_summary(summary, parsed)
    return Report(
        file_name=file_name,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        report_format=TRIVY_TEXT,
        not_in_format=NOT_IN_TEXT + tuple(sorted(parsed.missing)),
        schema_version=None,
        trivy_version=None,
        created_at=None,
        artifact_name=None,
        artifact_type=None,
        os_family=None,
        os_name=None,
        repo_url=None,
        branch=None,
        commit=None,
        findings=tuple(parsed.findings),
        misconfigurations=tuple(parsed.misconfigurations),
        secrets=tuple(parsed.secrets),
        licenses=tuple(parsed.licenses),
        misconfig_passed=parsed.misconfig_passed,
        misconfig_exceptions=0,
    )


def read_summary(lines: list[str]) -> tuple[list[SummaryEntry], int]:
    """The "Report Summary" table (if any) and the index where the sections start.

    Each entry: target, type (None for "-") and the four counts (a "-" is 0).
    """
    for index, line in enumerate(lines):
        if heading_at(lines, index):
            return [], 0
        if line.strip() == "Report Summary":
            top = next_content(lines, index + 1)
            if top >= len(lines) or not lines[top].startswith("┌"):
                raise ReportError("the Report Summary has no table")
            header, rows, after = read_table(lines, top, "Report Summary")
            if header[:2] != ["Target", "Type"] or header[2:] != list(SUMMARY_COUNTS[: len(header) - 2]) or len(header) < 5:
                raise ReportError("the Report Summary has unexpected columns")
            # Some layouts have no Licenses column: its count is 0.
            entries = [
                (" ".join(row[0]), type_or_none(" ".join(row[1])),
                 [count(" ".join(cell)) for cell in row[2:]] + [0] * (6 - len(header)))
                for row in rows
            ]
            return entries, after
    return [], 0


def type_or_none(text: str) -> str | None:
    return None if text in ("", "-") else text


def count(text: str) -> int:
    return int(text) if text.isdigit() else 0


def resolve_heading(heading: str, summary: list[SummaryEntry]) -> Heading:
    """Target, type and class of a result from its heading.

    The Report Summary gives them exactly. Without it, a bracket without
    spaces is a type or a class ("Python (python-pkg)"); a bracket with
    spaces belongs to the target ("python:3.9-slim (debian 13.1)").
    """
    for target, result_type, _ in summary:
        if heading == target:
            return Heading(target, result_type, None)
        if result_type and heading == f"{target} ({result_type})":
            return Heading(target, result_type, None)
    match = HEADING_BRACKET.match(heading)
    if match is None:
        return Heading(heading, None, None)
    target, bracket = match.groups()
    if bracket in CLASS_WORDS:
        return Heading(target, None, bracket)
    return Heading(target, bracket, None)


def parse_section(lines: list[str], start: int, end: int, summary: list[SummaryEntry], parsed: Parsed) -> None:
    """Parse one result section (heading at `start`, body up to `end`)."""
    title = lines[start].strip()
    heading = resolve_heading(title, summary)
    first = next_content(lines, start + 2)
    if first >= end:
        raise ReportError(f"{title}: the section is empty")
    if lines[first].startswith("Tests:"):
        parse_misconfigurations(lines, first, end, heading, title, parsed)
        return
    total = TOTAL.match(lines[first].strip())
    if total is None:
        raise ReportError(f"{title}: expected a Total or Tests line")
    expected = [int(number) for number in total.groups()]
    after = next_content(lines, first + 1)
    if after < end and lines[after].startswith("┌"):
        header, rows, _ = read_table(lines, after, title)
        if header == VULN_HEADER:
            parse_vulnerabilities(rows, heading, title, expected, parsed)
        elif header == LICENSE_HEADER:
            parse_licenses(rows, heading, title, expected, parsed)
        else:
            raise ReportError(f"{title}: unexpected table columns ({', '.join(header)})")
    else:
        parse_secrets(lines, after, end, heading, title, expected, parsed)


def check_total(
    title: str, what: str, severities: list[str], expected: list[int], may_be_fewer: bool = False
) -> None:
    """The section's own Total line must match the rows read (owner's decision B).

    Vulnerability tables may show FEWER rows than their Total: Trivy draws an
    identical row under another one as blank lines, and still counts it
    (image.json: 12 in the total, 11 rows). Never more rows than the total.
    """
    found = [sum(1 for s in severities if s == name) for name in SEVERITY_ORDER]
    if may_be_fewer:
        mismatch = len(severities) > expected[0] or any(f > e for f, e in zip(found, expected[1:]))
    else:
        mismatch = expected[0] != len(severities) or expected[1:] != found
    if mismatch:
        raise ReportError(
            f"{title}: the {what} read ({len(severities)}) do not match the table's own total ({expected[0]}), "
            "so the file may be cut short or edited"
        )


def cell(row: Row, column: int) -> str:
    return " ".join(row[column])


def title_and_url(lines: list[str]) -> tuple[str | None, str | None]:
    """The title lines, then the primary URL (its wrapped parts join without a space).

    A second layout writes the link as "-->avd.aquasec.com/nvd/cve-..." (no
    scheme). Only that host gets "https://"; any other host gives no link.
    """
    for number, text in enumerate(lines):
        if text.startswith(("http://", "https://")):
            return " ".join(lines[:number]) or None, "".join(lines[number:])
        if text.startswith("-->"):
            rest = "".join(lines[number:])[3:]
            url = f"https://{rest}" if rest.split("/", 1)[0] == AVD_HOST else None
            return " ".join(lines[:number]) or None, url
    return " ".join(lines) or None, None


def parse_vulnerabilities(rows: list[Row], heading: Heading, title: str, expected: list[int], parsed: Parsed) -> None:
    items = []
    previous_library = ""
    for row in rows:
        vuln_id = cell(row, 1)
        if not vuln_id:
            raise ReportError(f"{title}: a table row has no vulnerability ID")
        # A blank Library cell means the package of the row above (this layout does not merge it).
        library = cell(row, 0) or previous_library
        previous_library = library
        file_suffix = LIBRARY_FILE.match(library)  # "jaraco.context (METADATA)": a file name
        text, url = title_and_url(row[6])
        items.append(
            Finding(
                fingerprint="",  # class is missing: "not in this format"
                target=heading.target,
                vuln_class=None,
                vuln_type=heading.result_type,
                vuln_id=vuln_id,
                pkg_name=(file_suffix.group(1) if file_suffix else library) or None,
                installed_version=cell(row, 4) or None,
                fixed_version=cell(row, 5) or None,
                status="".join(row[3]) or "unknown",  # a status has no space: a wrap can fall inside it
                severity=normalize_severity(cell(row, 2)),
                title=text,
                cvss_score=None,
                primary_url=url,
                published_date=None,
            )
        )
    check_total(title, "vulnerabilities", [f.severity for f in items], expected, may_be_fewer=True)
    parsed.findings.extend(items)


def parse_licenses(rows: list[Row], heading: Heading, title: str, expected: list[int], parsed: Parsed) -> None:
    items = []
    for row in rows:
        name = cell(row, 1)
        items.append(
            License(
                fingerprint="",
                target=heading.target,
                license_class=heading.class_word or "license",
                pkg_name=cell(row, 0) or None,
                file_path=None,
                name=name or None,
                category=cell(row, 2).lower() or None,
                severity=normalize_severity(cell(row, 3)),
                confidence=None,
                link=None,
            )
        )
    check_total(title, "licenses", [x.severity for x in items], expected)
    parsed.licenses.extend(items)


def block_starts(lines: list[str], start: int, end: int, *heads: re.Pattern[str]) -> list[int]:
    """Indexes of the block headers: a line that matches a header shape, then a line of "═"."""
    return [
        i for i in range(start, end)
        if any(head.match(lines[i].strip()) for head in heads) and is_rule(lines, i + 1, "═")
    ]


def parse_misconfigurations(
    lines: list[str], first: int, end: int, heading: Heading, title: str, parsed: Parsed
) -> None:
    tests = TESTS.match(lines[first].strip())
    if tests is None:
        raise ReportError(f"{title}: the Tests line is not understood")
    failures_line = next_content(lines, first + 1)
    failures = FAILURES.match(lines[failures_line].strip()) if failures_line < end else None
    items = []
    starts = block_starts(lines, first, end, MISCONFIG_HEAD, MISCONFIG_HEAD_PLAIN)
    for number, start in enumerate(starts):
        stop = starts[number + 1] if number + 1 < len(starts) else end
        head = lines[start].strip()
        with_id = MISCONFIG_HEAD.match(head)
        # The text after the colon is the check's Message: it can quote the
        # scanned file, so it is never kept (secrets rule, owner 2026-11-11).
        if with_id is not None:
            check_id, severity, _message = with_id.groups()
        else:
            plain = MISCONFIG_HEAD_PLAIN.match(head)
            assert plain is not None
            severity, _message = plain.groups()
            check_id = None  # this layout prints no check ID
            parsed.missing.add("check_id")
        # Between the "═" line and the first "─" line: description and "See <url>".
        # Everything after it (location, source lines) is never read.
        body = []
        index = start + 2
        while index < stop and not is_rule(lines, index, "─"):
            body.append(lines[index].strip())
            index += 1
        url_lines = [t for t in body if t.startswith("See http")]
        description = " ".join(t for t in body if t and not t.startswith("See http"))
        url = url_lines[-1][4:] if url_lines else None
        items.append(
            Misconfiguration(
                fingerprint="",
                target=heading.target,
                misconf_type=heading.result_type,
                check_type=None,
                check_id=check_id or None,
                title=None,
                description=description or None,
                resolution=None,
                severity=normalize_severity(severity),
                status="FAIL",
                primary_url=url,
                references=(url,) if url else (),
                resource=None,
                start_line=None,
                end_line=None,
            )
        )
    wanted = int(tests.group(2))
    if len(items) != wanted:
        raise ReportError(f"{title}: the failed checks read ({len(items)}) do not match the table's own total ({wanted})")
    if failures is not None:
        check_total(title, "failed checks", [m.severity for m in items], [int(n) for n in failures.groups()])
    parsed.misconfigurations.extend(items)
    parsed.misconfig_passed += int(tests.group(1))


def parse_secrets(
    lines: list[str], first: int, end: int, heading: Heading, title: str, expected: list[int], parsed: Parsed
) -> None:
    items = []
    starts = block_starts(lines, first, end, SECRET_HEAD, SECRET_HEAD_BRACKET)
    for number, start in enumerate(starts):
        stop = starts[number + 1] if number + 1 < len(starts) else end
        head = lines[start].strip()
        with_rule = SECRET_HEAD.match(head)
        header_title = None
        if with_rule is not None:
            severity, category, rule_id = with_rule.groups()
        else:
            bracket = SECRET_HEAD_BRACKET.match(head)
            assert bracket is not None
            severity, category, header_title = bracket.groups()
            rule_id = ""  # this layout prints no rule ID; its title is in the header
            parsed.missing.add("rule_id")
        # Title: lines up to the first "─" line. Then the location line, if any.
        # The source lines after it are never read: they can hold the secret.
        index = start + 2
        title_lines = []
        while index < stop and not is_rule(lines, index, "─"):
            title_lines.append(lines[index].strip())
            index += 1
        has_location = index + 1 < stop and not is_rule(lines, index + 1, "─")
        location = LOCATION.match(lines[index + 1]) if has_location else None
        first_line = int(location.group(1)) if location else None
        last_line = (int(location.group(2)) if location.group(2) else first_line) if location else None
        items.append(
            Secret(
                fingerprint="",
                target=heading.target,
                rule_id=rule_id or None,
                category=category or None,
                severity=normalize_severity(severity),
                title=header_title.strip() or None if header_title is not None else " ".join(t for t in title_lines if t) or None,
                start_line=first_line,
                end_line=last_line,
            )
        )
    check_total(title, "secrets", [s.severity for s in items], expected)
    parsed.secrets.extend(items)


def check_summary(summary: list[SummaryEntry], parsed: Parsed) -> None:
    """The Report Summary counts must match what the sections gave (a cut file shows here).

    Vulnerabilities may be fewer than listed, as in a section's own Total.
    """
    if not summary:
        return
    wanted = [sum(entry[2][kind] for entry in summary) for kind in range(4)]
    found = [len(parsed.findings), len(parsed.misconfigurations), len(parsed.secrets), len(parsed.licenses)]
    for name, want, got in zip(("vulnerabilities", "misconfigurations", "secrets", "licenses"), wanted, found):
        # Vulnerabilities: an identical row drawn as blank lines is counted but not read.
        if got > want or (got != want and name != "vulnerabilities"):
            raise ReportError(
                f"the Report Summary lists {want} {name} but {got} were read, so the file may be cut short"
            )
