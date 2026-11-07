# Trivy report prototype

Upload a Trivy JSON vulnerability report in the browser, see the
vulnerabilities grouped by package, and see how to fix them.

> Work in progress. This README is completed in the last step.

## How to run (Windows, PowerShell)

Needs Python 3.11+ and Node.js 20.19+ or 22.12+.

**First time only**

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd ..\frontend
npm install
```

**Start the backend** (terminal 1, from the project folder):

```powershell
cd backend
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**Start the frontend** (terminal 2, from the project folder):

```powershell
cd frontend
npm run dev
```

Then open http://localhost:5173. The page shows "Ready: backend is running"
when both are up.

**Run the backend tests** (from `backend`):

```powershell
.venv\Scripts\python -m unittest discover -s tests -t .
```

The tests that need the real reports read them from the folder in the
`TRIVY_REPORTS_DIR` environment variable (default: the folder that contains
this project) and are skipped if `image.json` and `fs.json` are not there.

**Run the frontend tests** (from `frontend`):

```powershell
npm test
```
