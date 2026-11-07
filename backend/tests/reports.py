"""Where the tests find the real Trivy reports (not in the repository).

fs.json holds personal git data, so the reports stay outside git. Point
TRIVY_REPORTS_DIR at the folder that holds them; by default the folder that
contains this project is used.
"""

import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
REPORTS_DIR = Path(os.environ.get("TRIVY_REPORTS_DIR", PROJECT_DIR.parent))
IMAGE_JSON = REPORTS_DIR / "image.json"
FS_JSON = REPORTS_DIR / "fs.json"
REAL_REPORTS_FOUND = IMAGE_JSON.exists() and FS_JSON.exists()
SKIP_REASON = (f"real reports not found in {REPORTS_DIR} "
               "(set TRIVY_REPORTS_DIR)")
