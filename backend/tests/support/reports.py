"""Where the tests find the real Trivy reports (not in the repository).

fs.json holds personal git data, so the reports stay outside git. Point
TRIVY_REPORTS_DIR at the folder that holds them; by default the folder that
contains this project is used.
"""

import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[3]
REPORTS_DIR = Path(os.environ.get("TRIVY_REPORTS_DIR", PROJECT_DIR.parent))
IMAGE_JSON = REPORTS_DIR / "image.json"
FS_JSON = REPORTS_DIR / "fs.json"
REAL_REPORTS_FOUND = IMAGE_JSON.exists() and FS_JSON.exists()
SKIP_REASON = (f"real reports not found in {REPORTS_DIR} "
               "(set TRIVY_REPORTS_DIR)")

# Trivy's own sample reports and the owner's synthetic report (U2), in the
# "samples" folder next to the real reports; see SOURCES.txt there.
SAMPLES_DIR = REPORTS_DIR / "samples"
SAMPLES_FOUND = (SAMPLES_DIR / "SOURCES.txt").exists()
SAMPLES_SKIP_REASON = f"sample reports not found in {SAMPLES_DIR}"

# Trivy's text (table) output made from those reports (U3b); see SOURCES.txt.
TABLES_DIR = SAMPLES_DIR / "tables"
TABLES_FOUND = REAL_REPORTS_FOUND and SAMPLES_FOUND and (TABLES_DIR / "image.txt").exists()
TABLES_SKIP_REASON = f"sample tables not found in {TABLES_DIR}"
