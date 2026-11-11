"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from collections.abc import Awaitable, Callable
from pathlib import PureWindowsPath
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.parsers.models import Finding, ReportError
from fix_steps import SECRET_FIX_STEPS
from fixes import (FIX_SCHEMA, FixAdvice, FixError, FixGroup, build_messages,
                   validate_answer)
from llm_client import (LLMError, LLMSettings, chat_json, is_this_computer,
                        list_models)
from llm_config import current_settings
from report_formats import parse_report_file
from trivy_parser import (
    findings_by_group,
    group_by_package,
    group_key,
    summarize,
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
# A multipart request is a little bigger than the file inside it.
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 64 * 1024
TOO_LARGE = "The request is larger than 50 MB."
# Only this computer may use the backend: by host name (stops DNS
# rebinding) and, when a browser sends one, by page origin (stops other
# websites from posting here). The Vite dev page is the only page.
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}

app = FastAPI(title="Trivy report prototype")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


class ReportDetails(BaseModel):
    """What was scanned. Git author, committer and message are never here."""

    model_config = ConfigDict(from_attributes=True)

    file_name: str
    file_sha256: str
    report_format: str
    not_in_format: list[str]
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
    by_kind: dict[str, int]
    misconfig_passed: int
    misconfig_exceptions: int


class MisconfigurationOut(BaseModel):
    """One failed configuration check. No Message or code lines (they can quote a credential)."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    misconf_type: str | None
    check_type: str | None
    check_id: str | None
    title: str | None
    description: str | None
    resolution: str | None
    severity: str
    status: str
    primary_url: str | None
    references: list[str]
    resource: str | None
    start_line: int | None
    end_line: int | None


class SecretOut(BaseModel):
    """Where a secret is. This model has no field for its value (rule n)."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    rule_id: str | None
    category: str | None
    severity: str
    title: str | None
    start_line: int | None
    end_line: int | None


class LicenseOut(BaseModel):
    """One license of a package or found in a file."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    license_class: str | None
    pkg_name: str | None
    file_path: str | None
    name: str | None
    category: str | None
    severity: str
    confidence: float | None
    link: str | None


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
    misconfigurations: list[MisconfigurationOut]
    secrets: list[SecretOut]
    licenses: list[LicenseOut]
    secret_fix_steps: list[str]  # the same fixed steps for every secret


class LLMStatus(BaseModel):
    """Answer of "Check connection": the backend's own LLM, never its key."""

    model: str
    model_found: bool
    leaves_this_computer: bool  # the page then warns which data is sent


def llm_settings() -> LLMSettings:
    """The LLM chosen in llm_config.py; a setup problem gives one 503 line.

    A FastAPI dependency, so tests can swap in a fake Ollama with
    app.dependency_overrides.
    """
    try:
        return current_settings()
    except LLMError as error:
        raise HTTPException(status_code=503, detail=str(error)) from None


BackendLLM = Annotated[LLMSettings, Depends(llm_settings)]


@app.middleware("http")
async def check_request(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Refuse foreign pages and oversized POSTs before the body is read.

    FastAPI has no upload limit, and Starlette saves a file part to disk
    before the endpoint runs, so the size is checked from the header first.
    """
    origin = request.headers.get("origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return JSONResponse(
            {"detail": "Requests are only accepted from the local page."}, 403)
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
    if first["type"] == "json_invalid":
        return JSONResponse(
            {"detail": "The request body is not valid JSON."}, 422)
    parts = [str(part) for part in first["loc"] if part != "body"]
    field = ".".join(parts) or "request body"
    # Pydantic puts "Value error, " in front of our own validator messages.
    message = first["msg"].removeprefix("Value error, ")
    return JSONResponse({"detail": f"{field}: {message}"}, 422)


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


@app.post("/api/llm/check")
def llm_check(settings: BackendLLM) -> LLMStatus:
    """Check that the backend's LLM answers and has its model.

    A POST, not a GET: in api mode this sends the key to ollama.com, and a
    browser always sends the Origin of a cross-site POST, so the middleware
    can refuse other websites (a GET from an <img> carries no Origin).
    Uses Ollama's GET /api/tags, which is cheap: nothing is generated. A
    model name without a tag (e.g. "llama3.2") means its ":latest" tag.
    """
    try:
        models = list_models(settings)
    except LLMError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
    model = settings.model
    return LLMStatus(
        model=model,
        model_found=model in models or f"{model}:latest" in models,
        leaves_this_computer=not is_this_computer(settings.base_url),
    )


@app.post("/api/fix")
def fix(group: FixGroup, settings: BackendLLM) -> FixAdvice:
    """Ask the backend's LLM to explain the fix for one group, then check it.

    The body is the group only: the page cannot choose where it is sent.
    The page always shows Trivy's own fixed versions; this only adds the
    explanation. A version counts as a fix only if Trivy lists it.
    """
    try:
        answer = chat_json(settings, build_messages(group), FIX_SCHEMA)
        return validate_answer(answer, group)
    except (LLMError, FixError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
