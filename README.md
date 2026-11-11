# Trivy report viewer

Upload a Trivy vulnerability report (JSON) in the browser. The app shows
what was scanned, counts the vulnerabilities by severity, groups them by
package, ordered by severity, and shows how to fix each package: always
Trivy’s fixed versions, and an AI explanation from a local LLM (Ollama)
when you open a package.

This is a prototype: the smallest thing that works end to end. Everything
runs on your own computer. Nothing is saved.

## What it does

- **Upload** one Trivy JSON report. Other files get “only Trivy JSON reports
  are supported right now”.
- **Report details**: what was scanned, Trivy version, scan date, and the
  operating system or the git repository, branch and commit.
- **Counts** by severity: Critical, High, Medium and Low are ranked (levels
  4 to 1, higher is more severe); Unknown is shown apart, because Trivy
  could not rate it, and always comes after the rated ones.
- **Packages by severity**, with filters for severity and status. Each
  package shows Trivy’s fixed versions and opens to the list of its
  vulnerabilities.
- **AI explanation** when a package is opened: the LLM (`qwen3:8b`) explains
  the fix and suggests
  commands. The code, not the LLM, decides what counts as a fix: a version
  is shown as the recommended upgrade only if it is one of Trivy’s fixed
  versions. Every answer says “AI suggestion: verify before applying”, and
  commands are only shown, never run.
- **Download fix summary**: a Markdown file (`fix-summary-<report>.md`) of
  what the page shows (the filters apply): the report, the counts, and per
  package its fixed versions plus the AI verdict, advice and commands for every
  package explained so far. It is built in the browser; nothing is sent.
  Report and AI text in it are escaped, so it cannot contain links, HTML or
  hidden characters.
- The app works fully without an LLM; only the AI explanation needs one.

## How it is built

| Part | What it is |
|---|---|
| `backend/` | Python 3.11, FastAPI. `trivy_parser.py` (parse, group, count), `llm_client.py` (Ollama client), `fixes.py` (LLM request and answer check), `main.py` (the API) |
| `frontend/` | React + Vite + TypeScript. A sidebar (upload, AI status, filters) and the results (report, severity bar, packages with AI explanations) |

API: `GET /api/health`, `POST /api/analyze` (upload), `POST /api/llm/check`
(Check connection), `POST /api/fix` (AI explanation; the body is one
package). The browser talks only to the backend; the backend talks to Ollama.
The backend alone chooses the LLM (`backend/llm_config.py`): the page has no
LLM settings and never sees a key.

## Install (first time only)

Needs Python 3.11+ and Node.js 20.19+ or 22.12+. Commands are for Windows
PowerShell, run from the project folder.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd ..\frontend
npm install
```

For the AI explanation you also need [Ollama](https://ollama.com) and the
model the app uses, `qwen3:8b`:

```powershell
ollama pull qwen3:8b
```

## Run

**Terminal 1, backend:**

```powershell
cd backend
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**Terminal 2, frontend:**

```powershell
cd frontend
npm run dev
```

Open http://localhost:5173. The sidebar shows “Backend running” when both
are up. Stop each with Ctrl+C.

For the AI explanation, Ollama must be running (the Ollama app, or
`ollama serve` in a third terminal).

## Use

1. Drop a Trivy JSON report on the **Upload a report** panel in the sidebar (or
   click it to choose one) and click **Analyze report**.
2. Read the report details and the severity bar. Use the severity chips
   and the status list under **Filters** to narrow the packages.
3. Click a package name: its vulnerabilities show, and the AI explanation
   starts by itself (about 25 seconds; one package at a time, the others
   wait their turn). Answers are kept until the next upload.
4. **AI explanations** in the sidebar shows whether `qwen3:8b` is ready;
   the page checks this when it opens. **Check connection** checks again,
   for example after starting Ollama.

## Which AI model: local now, hosted API later

The backend reads the `LLM_MODE` environment variable when it handles a
request:

| `LLM_MODE` | LLM | Key |
|---|---|---|
| `local` (default) | Ollama on this computer, `http://localhost:11434`, model `qwen3:8b` | none |
| `api` | Ollama’s hosted API, `https://ollama.com`; model `OLLAMA_API_MODEL` (default `qwen3:8b`) | `OLLAMA_API_KEY` (from https://ollama.com/settings/keys) |

To use the hosted API, start the backend with the variables set, for
example in PowerShell:

```powershell
$env:LLM_MODE = "api"; $env:OLLAMA_API_KEY = "<your key>"
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

When the app has moved to the API for good, delete the “Local LLM” part of
`backend/llm_config.py` and its branch in `current_settings()`.

The key stays in the backend’s environment only: it is never sent to the
page, never logged, never put in a URL, and only sent over https. Nothing
reads `.env` files: set the variables in the shell that starts the backend,
and never write the key into a file in the repository. In `api` mode the page warns that the
opened package’s data leaves this computer. The Ollama docs say their cloud
does not support structured outputs yet, so answers from it may be refused
as “did not match the expected format”; it also only works if the service
offers the chosen model.

## Tests

Backend (from `backend`):

```powershell
.venv\Scripts\python -m unittest discover -s tests -t .
```

The tests that need the real reports read them from the folder in the
`TRIVY_REPORTS_DIR` environment variable (default: the folder that contains
this project) and are skipped if `image.json` and `fs.json` are not there.
The reports are not in the repository: `fs.json` holds personal git data.

Frontend (from `frontend`):

```powershell
npm test
```

## Command line

The parser also runs on its own and prints the same summary:

```powershell
cd backend
.venv\Scripts\python trivy_parser.py ..\..\image.json ..\..\fs.json --limit 5
```

`--json OUT.json` writes everything to a file.

## Security in short

- Uploaded files and every text in them are treated as untrusted: they are
  never run, never shown as HTML, limited to 50 MB, and invisible or
  right-to-left characters are shown as visible codes.
- The backend listens on 127.0.0.1 only and accepts only the local page
  (Host and Origin checks).
- Git author, committer and commit message are dropped as soon as a report
  is loaded.
- Only one package is ever sent to the LLM, as clearly marked data,
  and the model is told to ignore instructions inside it.

## Known limitations

- The AI text can be wrong (a small local model may misstate risks or
  suggest poor commands). The verdict about the version is made by code,
  but always read the AI text and commands critically.
- Ollama’s hosted cloud does not support structured outputs yet, so its
  answers may be refused.
- A local model needs time: about 20 to 25 seconds per package with qwen3:8b.
- The backend keeps no state, so it checks the AI’s version against the
  fixed versions the page sends back from the upload.
- While an upload is read, Starlette keeps files over 1 MB in a temporary
  file, deleted after the request.
- Versions are never compared (Trivy’s fixed versions are listed as text),
  and CVSS v4-only scores are not shown.

## Future scope

Not built in this prototype:

- A database with upload history.
- Tracking defects over time (new, still open, fixed, back again) and
  comparing reports. The `fingerprint` of each finding and the
  `file_sha256` of each report are kept for this.
- Several users and login.
- Report formats other than Trivy JSON.
- Agents or MCP integration.
