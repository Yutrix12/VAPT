"""Load a Trivy JSON report: read the bytes, drop private data, check the shape."""

import json
import reprlib
from pathlib import Path
from typing import Any, NoReturn

from app.parsers.models import ReportError

SUPPORTED_SCHEMA_VERSION = 2
# Personal data in repository scans: dropped as soon as the JSON is loaded.
GIT_PERSONAL_FIELDS = ("CommitMsg", "Author", "Committer")
# Secrets rule (rule n): the secret value lives in these fields of a
# secret; dropped as soon as the JSON is loaded, like the git data.
SECRET_VALUE_FIELDS = ("Match", "Code", "Offset")
# A misconfiguration can quote the scanned file: its cause's code lines
# (e.g. ENV PASSWORD=...) and its Message (Trivy's checks put the failing
# instruction in it, e.g. DS-0013 the whole RUN command). Both are dropped
# at load (owner's decisions 2026-11-11): only the problem and its place
# (check ID, title, description, resolution, file, lines) are used.
MISCONFIG_CODE_FIELDS = ("Code", "RenderedCause")
MISCONFIG_FILE_TEXT_FIELDS = ("Message",)


def is_result_list(items: Any) -> bool:
    """Return True if items is a list of result objects, each with a Target."""
    return isinstance(items, list) and all(
        isinstance(item, dict) and "Target" in item for item in items
    )


def to_report_dict(data: Any) -> dict[str, Any]:
    """Check parsed JSON is a Trivy report and return it with a Results list.

    New format: an object with SchemaVersion 2. Trivy leaves out Results
    when nothing was found, so a missing or null Results becomes an empty
    list. Old format: a non-empty list of result items, wrapped as
    {"Results": [...]} so later code handles one shape only.
    Raises ReportError with the reason if the data is neither.
    """
    if isinstance(data, dict):
        if "SchemaVersion" not in data:
            raise ReportError("not a Trivy JSON report (no SchemaVersion)")
        schema_version = data["SchemaVersion"]
        # The type check stops 2.0 (a float equal to 2) from passing.
        if not isinstance(schema_version, int) or (
            schema_version != SUPPORTED_SCHEMA_VERSION
        ):
            # reprlib.repr shortens a value from the file, so a huge value
            # still gives a short error line.
            raise ReportError(
                f"unsupported SchemaVersion {reprlib.repr(schema_version)} "
                f"(only {SUPPORTED_SCHEMA_VERSION} is supported)"
            )
        results = data.get("Results")
        if results is None:
            results = []
        if not is_result_list(results):
            raise ReportError(
                "not a Trivy JSON report "
                "(Results is not a list of result objects)"
            )
        return {**data, "Results": results}
    if isinstance(data, list) and data:
        if not is_result_list(data):
            raise ReportError(
                "not a Trivy JSON report (list items are not result objects)"
            )
        return {"Results": data}
    raise ReportError(
        "not a Trivy JSON report (expected an object or a list of results)"
    )


def drop_git_personal_data(data: Any) -> None:
    """Remove the git author, committer and commit message (rule l).

    Changes `data` in place. Called right after the JSON is parsed, before
    any other check, so nothing later can see or keep these fields.
    """
    if isinstance(data, dict):
        metadata = data.get("Metadata")
        if isinstance(metadata, dict):
            for key in GIT_PERSONAL_FIELDS:
                metadata.pop(key, None)


def objects_in(value: Any) -> list[dict[str, Any]]:
    """The dict items of a list (anything else is checked later)."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def drop_secret_values(data: Any) -> None:
    """Remove secret values and misconfiguration code lines (rule n).

    Changes `data` in place, right after the JSON is parsed (like
    drop_git_personal_data), so nothing later can see, keep, log or send
    them. Secrets lose Match, Code and Offset; misconfigurations lose their
    Message and their cause's code lines; licenses lose Text (long and not
    used).

    This walk runs before any parsing on purpose. A new finding kind with
    sensitive fields must be added here as well as in parse_results.
    """
    results = data.get("Results") if isinstance(data, dict) else data
    for result in objects_in(results):
        for secret in objects_in(result.get("Secrets")):
            for key in SECRET_VALUE_FIELDS:
                secret.pop(key, None)
        for misconfig in objects_in(result.get("Misconfigurations")):
            for key in MISCONFIG_FILE_TEXT_FIELDS:
                misconfig.pop(key, None)
            cause = misconfig.get("CauseMetadata")
            if isinstance(cause, dict):
                for key in MISCONFIG_CODE_FIELDS:
                    cause.pop(key, None)
        for license_item in objects_in(result.get("Licenses")):
            license_item.pop("Text", None)


def reject_json_constant(name: str) -> NoReturn:
    """Reject NaN, Infinity and -Infinity, which are not valid JSON."""
    raise ReportError(f"not valid JSON ({name} is not allowed)")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a key that appears twice.

    By default json.loads keeps only the last duplicate, which would lose
    data without any error.
    """
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ReportError(
                f"not valid JSON (duplicate key {reprlib.repr(key)})"
            )
        obj[key] = value
    return obj


def check_file_name(file_name: str) -> None:
    """Accept only .json file names; ReportError otherwise."""
    if not file_name.lower().endswith(".json"):
        raise ReportError("only Trivy JSON reports are supported right now")


def read_report_file(path: Path) -> bytes:
    """Return the bytes of a file; ReportError if it cannot be read."""
    try:
        return path.read_bytes()
    except OSError as error:
        reason = error.strerror or type(error).__name__
        raise ReportError(f"cannot read file ({reason})") from error


def load_json(raw: bytes) -> Any:
    """Parse raw file bytes as JSON (any JSON content).

    Raises ReportError with a one-line reason for any bad input.
    """
    try:
        # Given bytes, json.loads detects UTF-8, UTF-8 with BOM, UTF-16 and
        # UTF-32 by itself (json.detect_encoding), so no manual decoding.
        data = json.loads(
            raw,
            parse_constant=reject_json_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as error:
        raise ReportError(
            "file is not UTF-8, UTF-16 or UTF-32 text"
        ) from error
    except json.JSONDecodeError as error:
        # Python's message for a control character already ends in " at"
        # ("Invalid control character at"); drop it so it is not doubled.
        message = error.msg.removesuffix(" at")
        raise ReportError(
            f"not valid JSON ({message} at line {error.lineno}, "
            f"column {error.colno})"
        ) from error
    except ValueError as error:
        # Other bad values, e.g. an integer longer than Python's digit limit.
        raise ReportError(f"not valid JSON ({error})") from error
    except RecursionError as error:
        raise ReportError("JSON is nested too deeply") from error
    return data


def prepare_report_data(data: Any) -> dict[str, Any]:
    """Drop personal data and secret values (rules l, n), then check it is
    a Trivy JSON report; return it with a Results list."""
    drop_git_personal_data(data)
    drop_secret_values(data)
    return to_report_dict(data)


def decode_report_json(raw: bytes) -> dict[str, Any]:
    """Parse raw file bytes as a Trivy JSON report and return it as a dict.

    Raises ReportError with a one-line reason for any bad input.
    """
    return prepare_report_data(load_json(raw))


def is_trivy_json(data: Any) -> bool:
    """True if parsed JSON looks like a Trivy JSON report (new or old format).

    to_report_dict still checks the details (e.g. the SchemaVersion).
    """
    return (isinstance(data, dict) and "SchemaVersion" in data) or (
        is_result_list(data) and len(data) > 0)
