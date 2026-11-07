"""A small Ollama HTTP client (standard library only).

Facts about the Ollama API are in the ollama-api skill. Every failure
becomes one LLMError with a clear message that never contains the API key.
"""

import http.client
import ipaddress
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

TAGS_TIMEOUT = 10.0  # seconds; listing models is quick
CHAT_TIMEOUT = 120.0  # seconds; a local model on a CPU can be slow
MAX_ANSWER_BYTES = 5 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
TEMPERATURE = 0  # factual, repeatable answers (the Ollama docs suggest 0)
MAX_ERROR_TEXT = 200


class LLMError(Exception):
    """The LLM could not be reached or gave an unusable answer."""


def strip_control_chars(text: str, keep: str = "") -> str:
    """Keep printable characters only (plus those in `keep`, e.g. "\\n")."""
    return "".join(char for char in text
                   if char.isprintable() or char in keep)


def normalize_base_url(url: str) -> str:
    """Return the base URL without a trailing slash; only http(s) allowed."""
    url = url.strip().rstrip("/")
    if not url.isprintable() or " " in url:
        raise LLMError("The base URL must not contain spaces or control "
                       "characters.")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - reading it checks that the port is valid
    except ValueError:
        raise LLMError("The base URL is not a valid address, "
                       "e.g. http://localhost:11434") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LLMError("The base URL must start with http:// or https:// "
                       "and name a host, e.g. http://localhost:11434")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise LLMError("The base URL must not contain a user name, "
                       "password, query or fragment.")
    return url


def is_this_computer(url: str) -> bool:
    """True if the URL's host is localhost or a loopback address."""
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_api_key(key: str, base_url: str) -> None:
    """Refuse keys that cannot travel safely. The key is never echoed."""
    if not (key.isascii() and key.isprintable()) or " " in key:
        raise LLMError("The API key may only contain printable characters "
                       "without spaces.")
    if urlsplit(base_url).scheme != "https" and not is_this_computer(base_url):
        raise LLMError("An API key is only sent over https:// (or to this "
                       "computer), so it cannot be read on the network.")


@dataclass(frozen=True)
class LLMSettings:
    """Where Ollama is and which model to use. The key is hidden in repr.

    The values are checked and normalized once, when the settings are made.
    """

    base_url: str
    model: str
    api_key: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        base_url = normalize_base_url(self.base_url)
        key = (self.api_key or "").strip() or None
        if key is not None:
            check_api_key(key, base_url)
        # A frozen dataclass needs object.__setattr__ to store the cleaned
        # values.
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "model", self.model.strip())
        object.__setattr__(self, "api_key", key)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects: they could carry the API key elsewhere."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Built once; it keeps no data between requests.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _ollama_error_text(error: urllib.error.HTTPError) -> str:
    """Ollama's own short reason from an error body, cleaned, or ''."""
    try:
        body = json.loads(error.read(4096))
    except (OSError, ValueError):
        return ""
    finally:
        error.close()
    text = body.get("error") if isinstance(body, dict) else None
    if not isinstance(text, str):
        return ""
    # Untrusted text: keep printable characters only, and keep it short.
    return strip_control_chars(text)[:MAX_ERROR_TEXT]


def _http_error_message(error: urllib.error.HTTPError) -> str:
    """One line for an HTTP error answer from Ollama."""
    if 300 <= error.code < 400:
        error.close()
        return (f"Ollama answered with a redirect (HTTP {error.code}); "
                "redirects are not followed. Check the base URL.")
    reason = _ollama_error_text(error)
    if error.code in (401, 403):
        message = (f"Ollama refused the request (HTTP {error.code}). "
                   "Check the API key.")
    else:
        message = f"Ollama answered with HTTP {error.code}."
    return f"{message} Ollama says: {reason}" if reason else message


def _read_all(response: Any, deadline: float) -> bytes:
    """Read the answer in chunks, within a total time and size limit.

    read1() returns what has arrived so far, so the deadline is checked
    even when a server sends its answer very slowly.
    """
    chunks: list[bytes] = []
    size = 0
    while chunk := response.read1(READ_CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_ANSWER_BYTES:
            raise LLMError("Ollama's answer is too large.")
        if time.monotonic() > deadline:
            raise TimeoutError
        chunks.append(chunk)
    return b"".join(chunks)


def _send(settings: LLMSettings, path: str, body: dict[str, Any] | None,
          timeout: float) -> Any:
    """Send one request to Ollama and return the parsed JSON answer."""
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if settings.api_key:
        headers["Authorization"] = f"Bearer {settings.api_key}"
    request = urllib.request.Request(settings.base_url + path, data=data,
                                     headers=headers)
    deadline = time.monotonic() + timeout
    too_slow = f"Ollama did not answer within {timeout:g} seconds."
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = _read_all(response, deadline)
    except urllib.error.HTTPError as error:
        raise LLMError(_http_error_message(error)) from None
    except TimeoutError:
        raise LLMError(too_slow) from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise LLMError(too_slow) from None
        raise LLMError(f"Cannot reach Ollama at {settings.base_url} "
                       f"({error.reason}).") from None
    except (http.client.HTTPException, OSError) as error:
        # For example the connection was dropped, or the server does not
        # speak HTTP. The class name is enough; no request data is shown.
        raise LLMError(f"The connection to Ollama at {settings.base_url} "
                       f"failed ({type(error).__name__}).") from None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        # RecursionError: JSON nested too deeply for Python to read.
        raise LLMError("Ollama answered with invalid JSON.") from None


def require_model(settings: LLMSettings) -> None:
    """Chatting needs a model name (listing models does not)."""
    if not settings.model:
        raise LLMError("Enter a model name, e.g. llama3.2")


def list_models(settings: LLMSettings,
                timeout: float = TAGS_TIMEOUT) -> list[str]:
    """Names of the models Ollama has (GET /api/tags), sorted."""
    answer = _send(settings, "/api/tags", None, timeout)
    models = answer.get("models") if isinstance(answer, dict) else None
    if not isinstance(models, list):
        raise LLMError("Ollama's model list has an unexpected shape.")
    return sorted({model["name"] for model in models
                   if isinstance(model, dict)
                   and isinstance(model.get("name"), str)})


def chat_json(settings: LLMSettings, messages: list[dict[str, str]],
              schema: dict[str, Any],
              timeout: float = CHAT_TIMEOUT) -> dict[str, Any]:
    """Ask the model for an answer shaped by a JSON schema (POST /api/chat).

    Returns the parsed JSON object. It is not trusted: the caller validates
    every field.
    """
    require_model(settings)
    answer = _send(settings, "/api/chat", {
        "model": settings.model,
        "messages": messages,
        "stream": False,
        "format": schema,
        "options": {"temperature": TEMPERATURE},
    }, timeout)
    message = answer.get("message") if isinstance(answer, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise LLMError("Ollama's answer has no message content.")
    try:
        parsed = json.loads(content)
    except (ValueError, RecursionError):
        raise LLMError("The model's answer is not valid JSON.") from None
    if not isinstance(parsed, dict):
        raise LLMError("The model's answer is not a JSON object.")
    return parsed
