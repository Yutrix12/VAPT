"""Helpers every report format uses: severities, fingerprints, shared text."""

import hashlib
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")  # display order
# Severity levels: a higher number is more severe. UNKNOWN has no level:
# Trivy could not rate it, so it stays outside the ranking.
SEVERITY_LEVELS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# The value of a field the uploaded format does not carry (U3): shown as
# such, never guessed. Report.not_in_format names those fields.
NOT_IN_FORMAT = "not in this format"


def normalize_severity(value: Any) -> str:
    """Uppercase a known severity; anything else becomes UNKNOWN."""
    severity = value.upper() if isinstance(value, str) else ""
    return severity if severity in SEVERITIES else "UNKNOWN"


def make_fingerprint(*parts: str | None) -> str:
    """sha256 of the parts joined by "|", first 16 hex chars; None is ""."""
    text = "|".join(part or "" for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def severity_level(severity: str) -> int | None:
    """4 for CRITICAL down to 1 for LOW; None for UNKNOWN (not rated)."""
    return SEVERITY_LEVELS.get(severity)


def severity_sort_key(severity: str) -> tuple[int, int]:
    """Sort key: most severe first, and UNKNOWN after every rated severity."""
    level = severity_level(severity)
    if level is None:
        return (1, 0)  # not rated: after all rated severities
    return (0, -level)  # rated: the higher level first
