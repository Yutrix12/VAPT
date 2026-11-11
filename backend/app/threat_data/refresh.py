"""The refresh command: download the KEV and EPSS files into the data folder.

This is the ONLY code in the app that uses the network, and it runs only when
the owner starts it by hand (python -m app.threat_data refresh). A download is
checked with the same reader the app uses, and replaces the old file only if
it is good (written beside it first, then renamed), so a failed refresh never
damages the data that is already there.
"""

import http.client
import os
import tempfile
import time
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
TIMEOUT_SECONDS = 60  # per network operation
MAX_SECONDS = 300  # for one whole download
USER_AGENT = "trivy-report-prototype-refresh"


@dataclass(frozen=True)
class RefreshResult:
    source: str  # "kev" | "epss"
    ok: bool
    message: str


class HttpOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to an http or https address (the default also allows ftp)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 (urllib's signature)
        if urlsplit(newurl).scheme not in ("http", "https"):
            raise DataError(f"the server redirected to an address that is not http or https: {newurl[:40]!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def saving_error(error: OSError) -> DataError:
    """A local disk problem, told apart from a network problem (both are OSError)."""
    return DataError(f"the file cannot be saved ({type(error).__name__}); check the disk and the folder")


def download(url: str, target: Path, limit: int, timeout: float, max_seconds: float) -> int:
    """Save url to target (a new file); returns its size. Raises DataError with a clear message."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise DataError(f"only http or https addresses are used, not {url[:40]!r}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(HttpOnlyRedirects)
    # The timeout is per network operation, so the whole download also has a deadline.
    deadline = time.monotonic() + max_seconds
    try:
        out = target.open("wb")
    except OSError as error:
        raise saving_error(error) from None
    size = 0
    with out:
        try:
            with opener.open(request, timeout=timeout) as response:
                while chunk := response.read(1 << 16):
                    size += len(chunk)
                    if size > limit:
                        raise DataError(f"the download is larger than {limit // 1_000_000} MB, stopped")
                    if time.monotonic() > deadline:
                        raise DataError(f"the download is taking longer than {max_seconds:g} seconds, stopped")
                    try:
                        out.write(chunk)
                    except OSError as error:
                        raise saving_error(error) from None
                declared = response.headers.get("Content-Length", "")
                if declared.isdigit() and int(declared) != size:  # read() ends quietly when the server hangs up
                    raise DataError("the download was cut short; try again")
        except urllib.error.HTTPError as error:
            raise DataError(f"the server answered HTTP {error.code}") from None
        except OSError as error:  # also URLError, timeouts
            reason = getattr(error, "reason", error)
            raise DataError(f"the server cannot be reached ({type(reason).__name__}); check the connection") from None
        except http.client.HTTPException:
            raise DataError("the download was cut short; try again") from None
    return size


def refresh_one(source: str, url: str, folder: Path, limit: int, timeout: float, max_seconds: float) -> RefreshResult:
    label = LABELS[source]
    handle, name = tempfile.mkstemp(prefix=FILES[source] + ".", suffix=".part", dir=folder)
    os.close(handle)
    part = Path(name)
    try:
        size = download(url, part, limit, timeout, max_seconds)
        if source == "kev":
            ids, released = parse_kev(part.read_bytes())
            detail = f"{len(ids)} CVEs, released {released}"
        else:
            scores, score_date = read_epss(part, None)
            detail = f"{len(scores)} scores, dated {score_date}"
        try:
            os.replace(part, folder / FILES[source])
        except OSError as error:
            raise DataError(f"the file cannot be saved ({type(error).__name__}); is it in use or the folder read-only?") from None
        return RefreshResult(source, True, f"{label}: saved {FILES[source]} ({size // 1000} KB, {detail})")
    except DataError as error:
        return RefreshResult(source, False, f"{label}: FAILED, the old file (if any) is kept: {error}")
    finally:
        part.unlink(missing_ok=True)


def refresh(folder: Path, kev_url: str = SOURCES["kev"], epss_url: str = SOURCES["epss"],
            timeout: float = TIMEOUT_SECONDS, limits: dict[str, int] | None = None,
            max_seconds: float = MAX_SECONDS) -> list[RefreshResult]:
    """Download both files; one failing does not stop the other."""
    limits = limits or LIMITS
    folder.mkdir(parents=True, exist_ok=True)
    return [refresh_one("kev", kev_url, folder, limits["kev"], timeout, max_seconds),
            refresh_one("epss", epss_url, folder, limits["epss"], timeout, max_seconds)]
