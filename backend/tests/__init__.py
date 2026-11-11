"""Tests. The threat-data folder is pointed at an empty place first, so a real
backend/data/ (made by the refresh command) can never change a test result."""

import os
import tempfile

os.environ["THREAT_DATA_DIR"] = os.path.join(tempfile.gettempdir(), "trivy-prototype-tests-no-threat-data")
