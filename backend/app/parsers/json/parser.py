"""Turn a loaded Trivy JSON report into a Report (the one JSON parser)."""

import hashlib
import reprlib
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.parsers.common import make_fingerprint, normalize_severity
from app.parsers.json.fields import (
    get_confidence,
    get_count,
    get_line,
    get_list,
    get_object,
    get_text,
    get_text_list,
)
from app.parsers.json.loader import (
    check_file_name,
    load_json,
    prepare_report_data,
    read_report_file,
)
from app.parsers.models import (
    Finding,
    License,
    Misconfiguration,
    Report,
    ReportError,
    Secret,
)

# Misconfiguration statuses (Trivy v0.76.2 pkg/types/misconfiguration.go).
# Only FAIL is a finding; PASS and EXCEPTION are counted, not listed (rule m).
MISCONFIG_FAILED = "FAIL"
MISCONFIG_PASSED = "PASS"
MISCONFIG_EXCEPTION = "EXCEPTION"
TRIVY_JSON = "Trivy JSON"


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

    Uploads go through app.parsers.parse_report_file instead, which
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
