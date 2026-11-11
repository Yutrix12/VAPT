"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from pathlib import PureWindowsPath
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, UploadFile

from app.analysis.grouping import findings_by_group, group_by_package, group_key
from app.analysis.summary import summarize
from app.api.schemas import (
    AnalyzeResponse,
    LicenseOut,
    LLMStatus,
    MisconfigurationOut,
    PackageGroupOut,
    ReportDetails,
    SecretOut,
    Summary,
)
from app.middleware import MAX_UPLOAD_BYTES
from app.middleware import register as register_middleware
from app.parsers import parse_report_file
from app.parsers.models import ReportError
from fix_steps import SECRET_FIX_STEPS
from fixes import (FIX_SCHEMA, FixAdvice, FixError, FixGroup, build_messages,
                   validate_answer)
from llm_client import (LLMError, LLMSettings, chat_json, is_this_computer,
                        list_models)
from llm_config import current_settings


app = FastAPI(title="Trivy report prototype")
register_middleware(app)


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
