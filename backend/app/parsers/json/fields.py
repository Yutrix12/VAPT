"""Read single fields of a Trivy JSON report, with one-line errors."""

from typing import Any

from app.parsers.models import ReportError


def get_text(item: dict[str, Any], key: str, where: str) -> str | None:
    """Return item[key] as text, or None if it is missing or empty.

    Raises ReportError if the value is not text or holds broken characters
    (lone surrogates) that would crash hashing or printing later.
    """
    value = item.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ReportError(f"{where}: {key} is not text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ReportError(
            f"{where}: {key} contains invalid characters"
        ) from error
    return value


def get_list(item: dict[str, Any], key: str, where: str) -> list[Any]:
    """Return item[key] as a list; missing or null means an empty list."""
    value = item.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReportError(f"{where}: {key} is not a list")
    return value


def get_object(item: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    """Return item[key] as a dict; missing or null means an empty dict."""
    value = item.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ReportError(f"{where}: {key} is not an object")
    return value


def get_count(item: dict[str, Any], key: str, where: str) -> int | None:
    """Return item[key] as a whole number of 0 or more, or None if missing."""
    value = item.get(key)
    if value is None:
        return None
    # bool is a subclass of int in Python, so rule it out explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f"{where}: {key} is not a whole number")
    return value


def get_line(item: dict[str, Any], key: str, where: str) -> int | None:
    """A line number; missing or 0 (Trivy's "no line") is None (rule o)."""
    return get_count(item, key, where) or None


def get_text_list(item: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    """Return item[key] as a tuple of texts; missing or null is empty."""
    texts = []
    for value in get_list(item, key, where):
        text = get_text({key: value}, key, where)
        if text is not None:
            texts.append(text)
    return tuple(texts)


def get_confidence(item: dict[str, Any], where: str) -> float | None:
    """A license's Confidence: a number from 0 to 1, or None if missing."""
    value = item.get("Confidence")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ReportError(f"{where}: Confidence is not a number from 0 to 1")
    return float(value)
