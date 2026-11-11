"""Request checks: who may call the API, how big a request may be, and the
one-line validation error."""

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
# A multipart request is a little bigger than the file inside it.
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 64 * 1024
TOO_LARGE = "The request is larger than 50 MB."
# Only this computer may use the backend: by host name (stops DNS
# rebinding) and, when a browser sends one, by page origin (stops other
# websites from posting here). The Vite dev page is the only page.
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}


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


def register(app: FastAPI) -> None:
    """Add the checks to the app. The order matters: the host check is added
    first, so the origin and size check runs before it."""
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
    app.middleware("http")(check_request)
    app.exception_handler(RequestValidationError)(one_line_validation_error)
