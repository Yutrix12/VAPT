"""Detect an uploaded report's format from its CONTENT and parse it.

The file name and its extension never decide (owner's brief A). Every
parser returns the same Report structure (app.parsers.models), so the API and the
page do not care which format was uploaded. Supported: Trivy JSON and
Trivy's text (table) output; SUPPORTED_FORMATS lists them for the error
message.
"""

# Not `import json`: importing the app.parsers.json package below would bind
# that name here and hide the standard library's json.
from json import detect_encoding

from app.parsers.common import NOT_IN_FORMAT
from app.parsers.json.loader import is_trivy_json, load_json
from app.parsers.json.parser import TRIVY_JSON, parse_report_data
from app.parsers.models import Report, ReportError
from app.parsers.text.parser import TRIVY_TEXT, decode_text, is_trivy_text, parse_report_text

__all__ = ["NOT_IN_FORMAT", "SUPPORTED_FORMATS", "parse_report_file"]

SUPPORTED_FORMATS = (TRIVY_JSON, TRIVY_TEXT)
BYTE_ORDER_MARK = chr(0xFEFF)


def unsupported() -> ReportError:
    return ReportError("not a supported Trivy report. Supported formats: " + ", ".join(SUPPORTED_FORMATS))


def looks_like_json(raw: bytes) -> bool:
    """True if the content starts like JSON ({ or [), in any JSON encoding.

    Then a parse error is reported as broken JSON, not as an unknown format.
    """
    start = raw[:64]
    try:
        text = start.decode(detect_encoding(start), errors="ignore")
    except LookupError:
        return False
    return text.lstrip(BYTE_ORDER_MARK + " \t\r\n")[:1] in ("{", "[")


def parse_report_file(file_name: str, raw: bytes) -> Report:
    """Parse an uploaded report of any supported format.

    Raises ReportError with a one-line reason for any bad input.
    """
    try:
        data = load_json(raw)
    except ReportError:
        if looks_like_json(raw):
            raise  # broken JSON: the JSON error says where
        text = decode_text(raw)
        if text is not None and is_trivy_text(text):
            return parse_report_text(file_name, raw, text)
        raise unsupported() from None
    if is_trivy_json(data):
        return parse_report_data(file_name, raw, data)
    raise unsupported()
