"""The refresh command: download the KEV and EPSS files into the data folder.

This is the ONLY code in the app that uses the network, and it runs only when
the owner starts it by hand (python -m app.threat_data refresh). A download is
checked with the same reader the app uses, and replaces the old file only if
it is good (written beside it first, then renamed), so a failed refresh never
damages the data that is already there.
"""

import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.threat_data.files import EPSS_FILE, KEV_FILE, DataError, parse_kev, read_epss

# Checked on 2026-11-11, see the threat-data skill.
SOURCES = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}
FILES = {"kev": KEV_FILE, "epss": EPSS_FILE}
LABELS = {"kev": "KEV", "epss": "EPSS"}
LIMITS = {"kev": 20_000_000, "epss": 100_000_000}  # bytes; the real files are about 1.5 MB and 2.8 MB
TIMEOUT_SECONDS = 60
USER_AGENT = "trivy-report-prototype-refresh"


@dataclass(frozen=True)
class RefreshResult:
    source: str  # "kev" | "epss"
    ok: bool
    message: str


def download(url: str, target: Path, limit: int, timeout: float) -> int:
    """Save url to target (a new file); returns its size. Raises DataError with a clear message."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise DataError(f"only http or https addresses are used, not {url[:40]!r}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, target.open("wb") as out:
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > limit:
                    raise DataError(f"the download is larger than {limit // 1_000_000} MB, stopped")
                out.write(chunk)
    except urllib.error.HTTPError as error:
        raise DataError(f"the server answered HTTP {error.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as error:
        reason = getattr(error, "reason", error)
        raise DataError(f"the server cannot be reached ({type(reason).__name__}); check the connection") from None
    return size


def refresh_one(source: str, url: str, folder: Path, limit: int, timeout: float) -> RefreshResult:
    label = LABELS[source]
    handle, name = tempfile.mkstemp(prefix=FILES[source] + ".", suffix=".part", dir=folder)
    os.close(handle)
    part = Path(name)
    try:
        size = download(url, part, limit, timeout)
        if source == "kev":
            ids, released = parse_kev(part.read_bytes())
            detail = f"{len(ids)} CVEs, released {released}"
        else:
            scores, score_date = read_epss(part, None)
            detail = f"{len(scores)} scores, dated {score_date}"
        os.replace(part, folder / FILES[source])
        return RefreshResult(source, True, f"{label}: saved {FILES[source]} ({size // 1000} KB, {detail})")
    except DataError as error:
        return RefreshResult(source, False, f"{label}: FAILED, the old file (if any) is kept: {error}")
    finally:
        part.unlink(missing_ok=True)


def refresh(folder: Path, kev_url: str = SOURCES["kev"], epss_url: str = SOURCES["epss"],
            timeout: float = TIMEOUT_SECONDS, limits: dict[str, int] | None = None) -> list[RefreshResult]:
    """Download both files; one failing does not stop the other."""
    limits = limits or LIMITS
    folder.mkdir(parents=True, exist_ok=True)
    return [refresh_one("kev", kev_url, folder, limits["kev"], timeout),
            refresh_one("epss", epss_url, folder, limits["epss"], timeout)]
