"""POST /api/analyze."""

from pathlib import PureWindowsPath

from fastapi import APIRouter, HTTPException, UploadFile

from app.analysis.grouping import findings_by_group, group_by_package, group_key
from app.analysis.summary import summarize
from app.api.schemas import (
    AnalyzeResponse,
    FindingOut,
    FindingThreat,
    FixCommandOut,
    LicenseOut,
    MisconfigurationOut,
    PackageGroupOut,
    ReportDetails,
    SecretOut,
    Summary,
    ThreatDataOut,
    ThreatSourceOut,
)
from app.fixes.commands import build_fix_commands
from app.fixes.secret_steps import SECRET_FIX_STEPS
from app.middleware import MAX_UPLOAD_BYTES
from app.parsers import parse_report_file
from app.parsers.models import Finding, PackageGroup, ReportError
from app.threat_data.files import CVE_ID, ThreatData, load_threat_data

router = APIRouter()


def finding_out(finding: Finding, threat: ThreatData) -> FindingOut:
    """A finding with its KEV/EPSS answer (left out when no data file is loaded)."""
    answer = threat.lookup(finding.vuln_id or "")
    if answer is None:
        return FindingOut(**vars(finding))
    return FindingOut(**vars(finding), threat=FindingThreat(**vars(answer)))


def package_group_out(group: PackageGroup, findings: list[Finding], threat: ThreatData) -> PackageGroupOut:
    """A group with its findings and the commands built from its fixed versions."""
    built = build_fix_commands(group.pkg_name, findings[0].vuln_type, list(group.fixed_versions))
    return PackageGroupOut(
        **vars(group),
        findings=[finding_out(finding, threat) for finding in findings],
        fix_commands=[FixCommandOut(label=c.label, version=c.version, lines=list(c.lines)) for c in built.commands],
        fix_commands_note=built.note,
    )


@router.post("/api/analyze", response_model_exclude_unset=True)  # leaves out the KEV/EPSS fields when unset
def analyze(file: UploadFile) -> AnalyzeResponse:
    """Parse one uploaded Trivy JSON report; nothing is saved."""
    # Keep only the name, in case a path was sent. PureWindowsPath splits
    # on both \ and / on every operating system.
    file_name = PureWindowsPath(file.filename or "").name or "upload"
    raw = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413,
                            detail="The file is larger than 50 MB.")
    try:
        report = parse_report_file(file_name, raw)
    except ReportError as error:
        raise HTTPException(status_code=422,
                            detail=f"Skipped {file_name}: {error}") from error

    # Local files only: nothing is downloaded here (see app.threat_data).
    wanted = {f.vuln_id for f in report.findings if f.vuln_id and CVE_ID.fullmatch(f.vuln_id)}
    threat = load_threat_data(wanted)
    grouped = findings_by_group(report)
    groups = [package_group_out(group, grouped[group_key(group)], threat) for group in group_by_package(report)]
    shown = None if threat.kev.status == threat.epss.status == "not_loaded" else ThreatDataOut(
        kev=ThreatSourceOut(**vars(threat.kev)), epss=ThreatSourceOut(**vars(threat.epss)))
    return AnalyzeResponse(
        report=ReportDetails.model_validate(report),
        summary=Summary(**summarize(report)),
        package_groups=groups,
        misconfigurations=[MisconfigurationOut.model_validate(m) for m in report.misconfigurations],
        secrets=[SecretOut.model_validate(s) for s in report.secrets],
        licenses=[LicenseOut.model_validate(lic) for lic in report.licenses],
        secret_fix_steps=list(SECRET_FIX_STEPS),
        **({} if shown is None else {"threat_data": shown}),
    )
