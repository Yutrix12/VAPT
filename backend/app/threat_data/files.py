"""The local KEV and EPSS files: where they are and how they are read.

Nothing here uses the network. The files are made by the refresh command
(app.threat_data.refresh), which the owner runs by hand. Formats: see the
threat-data skill (CISA KEV JSON feed, FIRST EPSS csv.gz).

A source is "loaded", "not_loaded" (no file) or "error" (a file that cannot
be used, with a message). A value is never guessed: with no data the answer
for a CVE is no answer at all.
"""

import csv
import gzip
import json
import os
import re
import zlib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

KEV_FILE = "known_exploited_vulnerabilities.json"
EPSS_FILE = "epss_scores-current.csv.gz"
STALE_AFTER_DAYS = 7  # older data is shown with its age and marked old
DEFAULT_DIR = Path(__file__).resolve().parents[2] / "data"  # backend/data, git-ignored

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
EPSS_FIRST_LINE = re.compile(r"#model_version:[^,]*,score_date:(\d{4}-\d{2}-\d{2})")
EPSS_HEADER = ["cve", "epss", "percentile"]


class DataError(Exception):
    """A data file cannot be used (bad input, not a bug). The message is shown on the page."""


@dataclass(frozen=True)
class Source:
    """What is known about one data file."""

    status: str  # "loaded" | "not_loaded" | "error"
    as_of: str | None = None  # the date inside the data (KEV dateReleased, EPSS score_date)
    age_days: int | None = None
    old: bool = False
    error: str | None = None


@dataclass(frozen=True)
class Threat:
    """What the data says about one vulnerability ID."""

    kev: str  # "listed" | "not_listed" | "no_data" | "not_cve"
    epss_state: str  # the same four
    epss: float | None  # only when epss_state is "listed"


@dataclass(frozen=True)
class ThreatData:
    kev: Source
    epss: Source
    kev_ids: frozenset[str] = frozenset()
    scores: dict[str, float] | None = None  # only the CVEs that were asked for

    def lookup(self, vuln_id: str) -> Threat | None:
        """The answer for one ID, or None when no file is loaded (nothing is guessed)."""
        if self.kev.status != "loaded" and self.epss.status != "loaded":
            return None
        if not CVE_ID.fullmatch(vuln_id):
            return Threat(*(("not_cve" if s.status == "loaded" else "no_data") for s in (self.kev, self.epss)), None)
        kev = "no_data" if self.kev.status != "loaded" else "listed" if vuln_id in self.kev_ids else "not_listed"
        if self.epss.status != "loaded":
            return Threat(kev, "no_data", None)
        score = (self.scores or {}).get(vuln_id)
        return Threat(kev, "not_listed" if score is None else "listed", score)


def data_dir() -> Path:
    """The folder with the files (THREAT_DATA_DIR if set; the tests use it)."""
    return Path(os.environ.get("THREAT_DATA_DIR") or DEFAULT_DIR)


def day_of(text: str, what: str) -> date:
    """The date at the start of a timestamp such as 2026-11-10T19:03:29.8375Z."""
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        raise DataError(f"{what} has no valid date: {text[:30]!r}") from None


def parse_kev(raw: bytes) -> tuple[frozenset[str], date]:
    """The CVE IDs of the KEV JSON feed and its release date."""
    try:
        feed = json.loads(raw)
    except ValueError:  # includes bad UTF-8
        raise DataError("KEV file is not valid JSON (download it again with the refresh command)") from None
    entries = feed.get("vulnerabilities") if isinstance(feed, dict) else None
    if not isinstance(entries, list) or not entries or not isinstance(feed.get("dateReleased"), str):
        raise DataError("KEV file is not the CISA KEV feed (no vulnerabilities list or dateReleased)")
    ids = []
    for entry in entries:
        cve = entry.get("cveID") if isinstance(entry, dict) else None
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
            raise DataError("KEV file has an entry without a valid cveID")
        ids.append(cve)
    return frozenset(ids), day_of(feed["dateReleased"], "KEV file")


def read_epss(path: Path, wanted: set[str] | None) -> tuple[dict[str, float], date]:
    """The scores of the wanted CVEs (all when wanted is None) and the score date.

    The whole file is read in a stream (about 400,000 rows) so that a damaged
    file is found, but only the wanted rows are kept.
    """
    scores: dict[str, float] = {}
    rows = 0
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
            found = EPSS_FIRST_LINE.match(stream.readline())
            if not found:
                raise DataError("EPSS file has no score_date line at the top")
            as_of = day_of(found.group(1), "EPSS file")
            reader = csv.reader(stream)
            if next(reader, None) != EPSS_HEADER:
                raise DataError("EPSS file does not have the columns cve,epss,percentile")
            for row in reader:
                if len(row) != 3 or not CVE_ID.fullmatch(row[0]):
                    raise DataError("EPSS file has a row that is not cve,epss,percentile")
                try:
                    score = float(row[1])
                except ValueError:
                    raise DataError("EPSS file has a score that is not a number") from None
                if not 0 <= score <= 1:  # also false for nan
                    raise DataError("EPSS file has a score outside 0 to 1")
                rows += 1
                if wanted is None or row[0] in wanted:
                    scores[row[0]] = score
    except (OSError, EOFError, zlib.error, UnicodeDecodeError, csv.Error):
        raise DataError("EPSS file is not a readable gzip CSV (download it again with the refresh command)") from None
    if rows == 0:
        raise DataError("EPSS file has no scores")
    return scores, as_of


def source_for(as_of: date, today: date) -> Source:
    age = (today - as_of).days
    return Source("loaded", as_of.isoformat(), age, age > STALE_AFTER_DAYS)


def load_threat_data(wanted: set[str], today: date | None = None) -> ThreatData:
    """Read both files for the wanted CVE IDs. Never raises for a bad file; never uses the network."""
    today = today or date.today()
    folder = data_dir()
    kev, kev_ids = Source("not_loaded"), frozenset[str]()
    epss, scores = Source("not_loaded"), None
    try:
        path = folder / KEV_FILE
        if path.is_file():
            kev_ids, released = parse_kev(path.read_bytes())
            kev = source_for(released, today)
    except DataError as error:
        kev, kev_ids = Source("error", error=str(error)), frozenset()
    except OSError:
        kev = Source("error", error="KEV file cannot be read")
    try:
        path = folder / EPSS_FILE
        if path.is_file():
            scores, score_date = read_epss(path, wanted)
            epss = source_for(score_date, today)
    except DataError as error:
        epss, scores = Source("error", error=str(error)), None
    return ThreatData(kev, epss, kev_ids, scores)
