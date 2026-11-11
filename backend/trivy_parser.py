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
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn


SUPPORTED_SCHEMA_VERSION = 2
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")  # display order
# Severity levels: a higher number is more severe. UNKNOWN has no level:
# Trivy could not rate it, so it stays outside the ranking.
SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
# Personal data in repository scans: dropped as soon as the JSON is loaded.
GIT_PERSONAL_FIELDS = ("CommitMsg", "Author", "Committer")
# Secrets rule (rule n): the secret value lives in these fields of a
# secret; dropped as soon as the JSON is loaded, like the git data.
SECRET_VALUE_FIELDS = ("Match", "Code", "Offset")
# A misconfiguration can quote the scanned file: its cause's code lines
# (e.g. ENV PASSWORD=...) and its Message (Trivy's checks put the failing
# instruction in it, e.g. DS-0013 the whole RUN command). Both are dropped
# at load (owner's decisions 2026-11-11): only the problem and its place
# (check ID, title, description, resolution, file, lines) are used.
MISCONFIG_CODE_FIELDS = ("Code", "RenderedCause")
MISCONFIG_FILE_TEXT_FIELDS = ("Message",)
# Misconfiguration statuses (Trivy v0.76.2 pkg/types/misconfiguration.go).
# Only FAIL is a finding; PASS and EXCEPTION are counted, not listed (rule m).
MISCONFIG_FAILED = "FAIL"
MISCONFIG_PASSED = "PASS"
MISCONFIG_EXCEPTION = "EXCEPTION"
TRIVY_JSON = "Trivy JSON"
# The value of a field the uploaded format does not carry (U3): shown as
# such, never guessed. Report.not_in_format names those fields.
NOT_IN_FORMAT = "not in this format"
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
class Misconfiguration:
    """One failed configuration check (Status FAIL) in one file.

    Its Message and code lines are never kept: they can quote a credential.
    """

    fingerprint: str
    target: str
    misconf_type: str | None  # the result's Type, e.g. "dockerfile"
    check_type: str | None  # e.g. "Dockerfile Security Check"
    check_id: str | None  # ID, or the older AVDID when ID is missing
    title: str | None
    description: str | None
    resolution: str | None  # Trivy's own fix text; None if not in the report
    severity: str
    status: str
    primary_url: str | None
    references: tuple[str, ...]
    resource: str | None
    start_line: int | None  # optional (rule o)
    end_line: int | None


@dataclass(frozen=True)
class Secret:
    """Where a secret was found. The secret value itself is never kept."""

    fingerprint: str
    target: str
    rule_id: str | None
    category: str | None
    severity: str
    title: str | None
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True)
class License:
    """One license of a package (PkgName) or found in a file (FilePath)."""

    fingerprint: str
    target: str
    license_class: str | None  # "license" or "license-file"
    pkg_name: str | None
    file_path: str | None
    name: str | None
    category: str | None
    severity: str
    confidence: float | None  # 0.0 to 1.0
    link: str | None


@dataclass(frozen=True)
class Report:
    """One parsed report. Git author, committer and message are never kept,
    and neither are secret values or misconfiguration code lines."""

    file_name: str
    file_sha256: str
    report_format: str  # e.g. "Trivy JSON", detected from the content (U3)
    not_in_format: tuple[str, ...]  # fields this format does not carry
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
    findings: tuple[Finding, ...]  # the vulnerabilities
    misconfigurations: tuple[Misconfiguration, ...]  # Status FAIL only
    secrets: tuple[Secret, ...]
    licenses: tuple[License, ...]
    misconfig_passed: int  # checks that passed (rule m): counted, not listed
    misconfig_exceptions: int  # checks with Status EXCEPTION: counted only

    @property
    def misconfig_count(self) -> int:
        """Listed (failed) misconfigurations; the page shows it until U5."""
        return len(self.misconfigurations)

    @property
    def secret_count(self) -> int:
        """Secrets found; the page shows it until U5."""
        return len(self.secrets)


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


def objects_in(value: Any) -> list[dict[str, Any]]:
    """The dict items of a list (anything else is checked later)."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def drop_secret_values(data: Any) -> None:
    """Remove secret values and misconfiguration code lines (rule n).

    Changes `data` in place, right after the JSON is parsed (like
    drop_git_personal_data), so nothing later can see, keep, log or send
    them. Secrets lose Match, Code and Offset; misconfigurations lose their
    Message and their cause's code lines; licenses lose Text (long and not
    used).

    This walk runs before any parsing on purpose. A new finding kind with
    sensitive fields must be added here as well as in parse_results.
    """
    results = data.get("Results") if isinstance(data, dict) else data
    for result in objects_in(results):
        for secret in objects_in(result.get("Secrets")):
            for key in SECRET_VALUE_FIELDS:
                secret.pop(key, None)
        for misconfig in objects_in(result.get("Misconfigurations")):
            for key in MISCONFIG_FILE_TEXT_FIELDS:
                misconfig.pop(key, None)
            cause = misconfig.get("CauseMetadata")
            if isinstance(cause, dict):
                for key in MISCONFIG_CODE_FIELDS:
                    cause.pop(key, None)
        for license_item in objects_in(result.get("Licenses")):
            license_item.pop("Text", None)


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


def load_json(raw: bytes) -> Any:
    """Parse raw file bytes as JSON (any JSON content).

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
    return data


def prepare_report_data(data: Any) -> dict[str, Any]:
    """Drop personal data and secret values (rules l, n), then check it is
    a Trivy JSON report; return it with a Results list."""
    drop_git_personal_data(data)
    drop_secret_values(data)
    return to_report_dict(data)


def decode_report_json(raw: bytes) -> dict[str, Any]:
    """Parse raw file bytes as a Trivy JSON report and return it as a dict.

    Raises ReportError with a one-line reason for any bad input.
    """
    return prepare_report_data(load_json(raw))


def is_trivy_json(data: Any) -> bool:
    """True if parsed JSON looks like a Trivy JSON report (new or old format).

    to_report_dict still checks the details (e.g. the SchemaVersion).
    """
    return (isinstance(data, dict) and "SchemaVersion" in data) or (
        is_result_list(data) and len(data) > 0)


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


def get_count(item: dict[str, Any], key: str, where: str) -> int | None:
    """Return item[key] as a whole number of 0 or more, or None if missing."""
    value = item.get(key)
    if value is None:
        return None
    # bool is a subclass of int in Python, so rule it out explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f"{where}: {key} is not a whole number")
    return value


def get_line(item: dict[str, Any], key: str, where: str) -> int | None:
    """A line number; missing or 0 (Trivy's "no line") is None (rule o)."""
    return get_count(item, key, where) or None


def get_text_list(item: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    """Return item[key] as a tuple of texts; missing or null is empty."""
    texts = []
    for value in get_list(item, key, where):
        text = get_text({key: value}, key, where)
        if text is not None:
            texts.append(text)
    return tuple(texts)


def get_confidence(item: dict[str, Any], where: str) -> float | None:
    """A license's Confidence: a number from 0 to 1, or None if missing."""
    value = item.get("Confidence")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ReportError(f"{where}: Confidence is not a number from 0 to 1")
    return float(value)


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


def parse_misconfiguration(
    item: dict[str, Any], target: str, result_type: str | None,
    numbers: Counter[tuple[str, str | None, str | None]], where: str,
) -> Misconfiguration:
    """Turn one listed (failed) Misconfigurations item into a Misconfiguration.

    Fingerprint (owner's OK, 2026-11-11): "config|type|file|check ID|
    resource|n", where n counts this check's failures for this resource in
    this file (1, 2, ...). No line numbers, so it stays the same when code
    moves; removing the first of two same failures renumbers the second.
    """
    cause = get_object(item, "CauseMetadata", where)
    check_id = get_text(item, "ID", where) or get_text(item, "AVDID", where)
    resource = get_text(cause, "Resource", where)
    numbers[(target, check_id, resource)] += 1
    occurrence = str(numbers[(target, check_id, resource)])
    return Misconfiguration(
        fingerprint=make_fingerprint("config", result_type, target, check_id, resource, occurrence),
        target=target,
        misconf_type=result_type,
        check_type=get_text(item, "Type", where),
        check_id=check_id,
        title=get_text(item, "Title", where),
        description=get_text(item, "Description", where),
        resolution=get_text(item, "Resolution", where),
        severity=normalize_severity(item.get("Severity")),
        status=MISCONFIG_FAILED,  # only failed checks are listed
        primary_url=get_text(item, "PrimaryURL", where),
        references=get_text_list(item, "References", where),
        resource=resource,
        start_line=get_line(cause, "StartLine", where),
        end_line=get_line(cause, "EndLine", where),
    )


def parse_secret(
    item: dict[str, Any], target: str, result_type: str | None, rule_id: str | None,
    occurrence: int, where: str,
) -> Secret:
    """Turn one Secrets item into a Secret, without its value (rule n).

    Fingerprint (owner's OK, 2026-11-11): "secret|type|file|rule ID|n",
    where n counts this rule's findings in this file (1, 2, ...). Never a
    line number, and never anything derived from the secret value: even a
    hash of a short secret can be guessed by trying values.
    """
    return Secret(
        fingerprint=make_fingerprint("secret", result_type, target, rule_id, str(occurrence)),
        target=target,
        rule_id=rule_id,
        category=get_text(item, "Category", where),
        severity=normalize_severity(item.get("Severity")),
        title=get_text(item, "Title", where),
        start_line=get_line(item, "StartLine", where),
        end_line=get_line(item, "EndLine", where),
    )


def parse_license(
    item: dict[str, Any], target: str, result_class: str | None, result_type: str | None, where: str,
) -> License:
    """Turn one Licenses item into a License.

    Fingerprint (owner's OK, 2026-11-11): "class|type|file|license name|
    package or file path".
    """
    pkg_name = get_text(item, "PkgName", where)
    file_path = get_text(item, "FilePath", where)
    name = get_text(item, "Name", where)
    return License(
        fingerprint=make_fingerprint(result_class, result_type, target, name, pkg_name or file_path),
        target=target,
        license_class=result_class,
        pkg_name=pkg_name,
        file_path=file_path,
        name=name,
        category=get_text(item, "Category", where),
        severity=normalize_severity(item.get("Severity")),
        confidence=get_confidence(item, where),
        link=get_text(item, "Link", where),
    )


@dataclass
class ParsedResults:
    """Everything parse_results collects from the Results list."""

    findings: list[Finding] = field(default_factory=list)
    misconfigurations: list[Misconfiguration] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    licenses: list[License] = field(default_factory=list)
    misconfig_passed: int = 0
    misconfig_exceptions: int = 0


def object_items(
    result: dict[str, Any], key: str, label: str, where: str,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Each item of result[key] with its place ("result 2, secret 1").

    Raises ReportError if an item is not a JSON object.
    """
    for number, item in enumerate(get_list(result, key, where), start=1):
        item_where = f"{where}, {label} {number}"
        if not isinstance(item, dict):
            raise ReportError(f"{item_where}: not an object")
        yield item_where, item


def parse_misconfigurations(
    result: dict[str, Any], target: str, result_type: str | None, where: str, parsed: ParsedResults,
    numbers: Counter[tuple[str, str | None, str | None]],
) -> None:
    """List the failed checks of one result; count the passed and excepted.

    Trivy (pkg/result/filter.go, v0.76.2) counts PASS in
    MisconfSummary.Successes and FAIL in Failures; EXCEPTION is in neither.
    It lists PASS and EXCEPTION items only with --include-non-failures, and
    listed PASS items are already in Successes, so they are not added again.
    """
    listed_passes = listed_exceptions = 0
    for item_where, item in object_items(result, "Misconfigurations", "misconfiguration", where):
        # Status first: counted items are not parsed further, so a broken
        # field that is never used cannot make the upload fail.
        status = (get_text(item, "Status", item_where) or "").upper()
        if status == MISCONFIG_PASSED:
            listed_passes += 1
        elif status == MISCONFIG_EXCEPTION:
            listed_exceptions += 1
        elif status == MISCONFIG_FAILED:
            parsed.misconfigurations.append(
                parse_misconfiguration(item, target, result_type, numbers, item_where))
        else:  # never guess what an unknown status means
            shown = reprlib.repr(status) if status else "missing"
            raise ReportError(f"{item_where}: Status is {shown} (expected PASS, FAIL or EXCEPTION)")
    summary_where = f"{where} MisconfSummary"
    summary = get_object(result, "MisconfSummary", where)
    successes = get_count(summary, "Successes", summary_where)
    # Exceptions: written by older Trivy versions (v0.30 to at least v0.50).
    exceptions = get_count(summary, "Exceptions", summary_where)
    parsed.misconfig_passed += listed_passes if successes is None else successes
    parsed.misconfig_exceptions += listed_exceptions if exceptions is None else exceptions


def parse_secrets(
    result: dict[str, Any], target: str, result_type: str | None, where: str,
    parsed: ParsedResults, numbers: Counter[tuple[str, str | None]],
) -> None:
    """List the secrets of one result; `numbers` counts each (file, rule)
    across the whole report, for the fingerprint's n."""
    for item_where, item in object_items(result, "Secrets", "secret", where):
        rule_id = get_text(item, "RuleID", item_where)
        numbers[(target, rule_id)] += 1
        parsed.secrets.append(
            parse_secret(item, target, result_type, rule_id, numbers[(target, rule_id)], item_where))


def parse_results(results: list[dict[str, Any]]) -> ParsedResults:
    """Go through all results once and collect every finding kind."""
    parsed = ParsedResults()
    # Occurrence numbers for the fingerprints, across the whole report.
    misconfig_numbers: Counter[tuple[str, str | None, str | None]] = Counter()
    secret_numbers: Counter[tuple[str, str | None]] = Counter()
    for result_number, result in enumerate(results, start=1):
        where = f"result {result_number}"
        target = get_text(result, "Target", where)
        if target is None:
            raise ReportError(f"{where}: Target is empty")
        vuln_class = get_text(result, "Class", where)
        vuln_type = get_text(result, "Type", where)
        vulns = get_list(result, "Vulnerabilities", where)
        for vuln_number, vuln in enumerate(vulns, start=1):
            parsed.findings.append(
                parse_finding(
                    vuln,
                    target,
                    vuln_class,
                    vuln_type,
                    f"{where}, vulnerability {vuln_number}",
                )
            )
        parse_misconfigurations(result, target, vuln_type, where, parsed, misconfig_numbers)
        parse_secrets(result, target, vuln_type, where, parsed, secret_numbers)
        for item_where, item in object_items(result, "Licenses", "license", where):
            parsed.licenses.append(parse_license(item, target, vuln_class, vuln_type, item_where))
    return parsed


def parse_report(path: Path) -> Report:
    """Read one Trivy JSON report file and return it as a Report.

    Raises ReportError with a one-line reason for any bad input.
    """
    # Check the name before reading, so a non-JSON file is never read.
    check_file_name(path.name)
    return parse_report_bytes(path.name, read_report_file(path))


def parse_report_bytes(file_name: str, raw: bytes) -> Report:
    """Parse the bytes of one Trivy JSON report file (the command line).

    Uploads go through report_formats.parse_report_file instead, which
    detects the format from the content. Raises ReportError with a
    one-line reason for any bad input.
    """
    check_file_name(file_name)
    return parse_report_data(file_name, raw, load_json(raw))


def parse_report_data(file_name: str, raw: bytes, loaded: Any) -> Report:
    """Build a Report from the loaded JSON of a Trivy JSON report.

    `raw` is only used for the file's sha256.
    """
    data = prepare_report_data(loaded)
    parsed = parse_results(data["Results"])

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
        report_format=TRIVY_JSON,
        not_in_format=(),
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
        findings=tuple(parsed.findings),
        misconfigurations=tuple(parsed.misconfigurations),
        secrets=tuple(parsed.secrets),
        licenses=tuple(parsed.licenses),
        misconfig_passed=parsed.misconfig_passed,
        misconfig_exceptions=parsed.misconfig_exceptions,
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
        # The other finding kinds (U2). The keys above count vulnerabilities
        # only, so their expected numbers never change.
        "by_kind": {
            "vulnerability": len(report.findings),
            "misconfiguration": len(report.misconfigurations),
            "secret": len(report.secrets),
            "license": len(report.licenses),
        },
        "misconfig_passed": report.misconfig_passed,
        "misconfig_exceptions": report.misconfig_exceptions,
    }


def severity_level(severity: str) -> int | None:
    """4 for CRITICAL down to 1 for LOW; None for UNKNOWN (not rated)."""
    return SEVERITY_LEVELS.get(severity)


def severity_sort_key(severity: str) -> tuple[int, int]:
    """Sort key: most severe first, and UNKNOWN after every rated severity."""
    level = severity_level(severity)
    if level is None:
        return (1, 0)  # not rated: after all rated severities
    return (0, -level)  # rated: the higher level first


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
        worst_severity=min((f.severity for f in findings),
                           key=severity_sort_key),
        fixed_versions=tuple(fixed_versions),
        has_unfixed=any(f.fixed_version is None for f in findings),
    )


def group_sort_key(
    group: PackageGroup,
) -> tuple[tuple[int, int], int, str, str, str]:
    """Sort key: worst severity, then most findings, then names for ties."""
    return (
        severity_sort_key(group.worst_severity),
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
