"""Detect an uploaded report's format from its CONTENT and parse it.

The file name and its extension never decide (owner's brief A). Every
parser returns the same Report structure (app.parsers.models), so the API and the
page do not care which format was uploaded. Supported (owner's decision
2026-11-11): Trivy JSON, Trivy's text (table) output and Trivy HTML from
html.tpl; text and HTML are added in the next sub-steps of U3, and
SUPPORTED_FORMATS lists only what already works, for the error message.
"""

# Not `import json`: importing the app.parsers.json package below would bind
# that name here and hide the standard library's json.
from json import detect_encoding

from app.parsers.common import NOT_IN_FORMAT
from app.parsers.json.loader import is_trivy_json, load_json
from app.parsers.json.parser import TRIVY_JSON, parse_report_data
from app.parsers.models import Report, ReportError

__all__ = ["NOT_IN_FORMAT", "SUPPORTED_FORMATS", "parse_report_file"]

SUPPORTED_FORMATS = (TRIVY_JSON,)
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
        raise unsupported() from None
    if is_trivy_json(data):
        return parse_report_data(file_name, raw, data)
    raise unsupported()
