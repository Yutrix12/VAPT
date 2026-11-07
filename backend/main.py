"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from collections.abc import Awaitable, Callable
from pathlib import PureWindowsPath

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from fixes import (FIX_SCHEMA, FixAdvice, FixError, FixGroup, build_messages,
                   validate_answer)
from llm_client import (LLMError, LLMSettings, chat_json, list_models,
                        require_model)
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


class LLMSettingsIn(BaseModel):
    """LLM settings sent by the page. SecretStr hides the key in logs."""

    base_url: str = Field(max_length=500)
    model: str = Field(max_length=200)
    api_key: SecretStr | None = Field(default=None, max_length=500)

    def to_client(self) -> LLMSettings:
        """Checked settings for llm_client; bad settings give a 422.

        LLMSettings does every check (URL, model, key) in one place.
        """
        key = self.api_key.get_secret_value() if self.api_key else None
        try:
            return LLMSettings(self.base_url, self.model, api_key=key)
        except LLMError as error:
            raise HTTPException(status_code=422, detail=str(error)) from None


class LLMTestResult(BaseModel):
    """Answer of "Test connection"."""

    ok: bool
    models: list[str]
    model_found: bool


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


@app.post("/api/llm/test")
def llm_test(settings: LLMSettingsIn) -> LLMTestResult:
    """Check that Ollama answers, and whether the chosen model exists.

    Uses GET /api/tags, which is cheap: nothing is generated. A model name
    without a tag (e.g. "llama3.2") means its ":latest" tag in Ollama.
    """
    client_settings = settings.to_client()
    try:
        models = list_models(client_settings)
    except LLMError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
    model = client_settings.model
    found = model in models or f"{model}:latest" in models
    return LLMTestResult(ok=True, models=models, model_found=found)


class FixRequest(BaseModel):
    """One package group plus the LLM settings to explain it with."""

    settings: LLMSettingsIn
    group: FixGroup


@app.post("/api/fix")
def fix(request: FixRequest) -> FixAdvice:
    """Ask the LLM to explain the fix for one group, then check the answer.

    The page always shows Trivy's own fixed versions; this only adds the
    explanation. A version counts as a fix only if Trivy lists it.
    """
    settings = request.settings.to_client()
    try:
        require_model(settings)
    except LLMError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    try:
        answer = chat_json(settings, build_messages(request.group),
                           FIX_SCHEMA)
        return validate_answer(answer, request.group)
    except (LLMError, FixError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
