"""Small KEV and EPSS data files for the tests, and a temporary data folder."""

import gzip
import json
import os
import tempfile
import unittest
from pathlib import Path

from app.threat_data.files import EPSS_FILE, KEV_FILE


def kev_json(ids: list[str], released: str = "2026-11-10T19:03:29.8375Z") -> bytes:
    """A CISA KEV feed with these CVE IDs (only the fields the app reads, plus a few it ignores)."""
    return json.dumps({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.11.10",
        "dateReleased": released,
        "count": len(ids),
        "vulnerabilities": [{"cveID": cve, "vendorProject": "Demo", "product": "Demo",
                             "dateAdded": "2026-01-01"} for cve in ids],
    }).encode("utf-8")


def epss_gz(scores: dict[str, str], score_date: str = "2026-11-11", header: str = "cve,epss,percentile") -> bytes:
    """A FIRST EPSS file: a comment line, the header, then one row per CVE (the score as text)."""
    lines = [f"#model_version:v2026.06.15,score_date:{score_date}T12:00:22Z", header]
    lines += [f"{cve},{score},0.5" for cve, score in scores.items()]
    return gzip.compress(("\n".join(lines) + "\n").encode("utf-8"))


class ThreatDataDirCase(unittest.TestCase):
    """A temporary data folder that the code under test reads (through THREAT_DATA_DIR)."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.data_dir = Path(self._temp.name) / "data"
        self.data_dir.mkdir()
        previous = os.environ["THREAT_DATA_DIR"]
        os.environ["THREAT_DATA_DIR"] = str(self.data_dir)
        self.addCleanup(os.environ.__setitem__, "THREAT_DATA_DIR", previous)

    def write_kev(self, raw: bytes) -> None:
        (self.data_dir / KEV_FILE).write_bytes(raw)

    def write_epss(self, raw: bytes) -> None:
        (self.data_dir / EPSS_FILE).write_bytes(raw)
