"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from collections.abc import Awaitable, Callable
from pathlib import PureWindowsPath

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from trivy_parser import (
    Finding,
    ReportError,
    findings_by_group,
    group_by_package,
    group_key,
    parse_report_bytes,
    summarize,
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
# A multipart request is a little bigger than the file inside it.
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 64 * 1024
TOO_LARGE = "The request is larger than 50 MB."

app = FastAPI(title="Trivy report prototype")


class ReportDetails(BaseModel):
    """What was scanned. Git author, committer and message are never here."""

    model_config = ConfigDict(from_attributes=True)

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


class Summary(BaseModel):
    """The counts from trivy_parser.summarize()."""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    unique_vuln_ids: int
    unique_packages: int
    without_fixed_version: int
    distinct_fingerprints: int


class PackageGroupOut(BaseModel):
    """One package group with the findings that belong to it."""

    model_config = ConfigDict(from_attributes=True)

    target: str
    pkg_name: str | None
    installed_version: str | None
    finding_count: int
    worst_severity: str
    fixed_versions: list[str]
    has_unfixed: bool
    findings: list[Finding]


class AnalyzeResponse(BaseModel):
    """Everything the results page shows for one report."""

    report: ReportDetails
    summary: Summary
    package_groups: list[PackageGroupOut]


@app.middleware("http")
async def limit_request_size(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Refuse an oversized POST before its body is read.

    FastAPI has no upload limit, and Starlette saves a file part to disk
    before the endpoint runs, so the size is checked from the header first.
    """
    if request.method == "POST":
        length = request.headers.get("content-length")
        if length is None:
            return JSONResponse(
                {"detail": "The request has no size (Content-Length)."}, 411)
        if not (length.isascii() and length.isdigit()):
            return JSONResponse(
                {"detail": "The request size (Content-Length) is invalid."},
                400)
        if int(length) > MAX_REQUEST_BYTES:
            return JSONResponse({"detail": TOO_LARGE}, 413)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def one_line_validation_error(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Send the first validation problem as one clear line.

    FastAPI's default lists every problem with the submitted values; only
    the field name and the reason are sent back here.
    """
    first = error.errors()[0]
    field = ".".join(str(part) for part in first["loc"] if part != "body")
    return JSONResponse({"detail": f"{field}: {first['msg']}"}, 422)


@app.get("/api/health")
async def health() -> dict[str, str]:
    """Tell the frontend that the backend is running."""
    return {"status": "ok"}


@app.post("/api/analyze")
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
        report = parse_report_bytes(file_name, raw)
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
    )
