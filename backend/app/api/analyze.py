"""POST /api/analyze."""

from pathlib import PureWindowsPath

from fastapi import APIRouter, HTTPException, UploadFile

from app.analysis.grouping import findings_by_group, group_by_package, group_key
from app.analysis.summary import summarize
from app.api.schemas import (
    AnalyzeResponse,
    LicenseOut,
    MisconfigurationOut,
    PackageGroupOut,
    ReportDetails,
    SecretOut,
    Summary,
)
from app.fixes.secret_steps import SECRET_FIX_STEPS
from app.middleware import MAX_UPLOAD_BYTES
from app.parsers import parse_report_file
from app.parsers.models import ReportError

router = APIRouter()


@router.post("/api/analyze")
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

    grouped = findings_by_group(report)
    groups = [
        PackageGroupOut(**vars(group), findings=grouped[group_key(group)])
        for group in group_by_package(report)
    ]
    return AnalyzeResponse(
        report=ReportDetails.model_validate(report),
        summary=Summary(**summarize(report)),
        package_groups=groups,
        misconfigurations=[MisconfigurationOut.model_validate(m) for m in report.misconfigurations],
        secrets=[SecretOut.model_validate(s) for s in report.secrets],
        licenses=[LicenseOut.model_validate(lic) for lic in report.licenses],
        secret_fix_steps=list(SECRET_FIX_STEPS),
    )
