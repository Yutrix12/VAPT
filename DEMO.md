# Demo script (about 5 minutes)

## Before the demo

1. Start Ollama (the Ollama app, or `ollama serve`). Make sure the model is
   there: `ollama list` should show `qwen3:8b`.
2. Start the backend and the frontend as in README.md ("Run").
3. Open http://localhost:5173 and check the green "Ready: backend is
   running".
4. **AI settings** should say "Connected: qwen3:8b is ready." (checked
   when the page opens).
5. Optional warm-up: open one small group once, so the model is loaded
   before the real demo (the first answer can take a minute).

## 1. A container image: image.json

1. Choose `image.json` and click **Analyze report**.
2. Point out:
   - **Report**: python:3.9-slim, a container image, scanned by Trivy
     0.76.2, Debian 13.1.
   - **Counts**: 492 findings in 54 packages: 6 CRITICAL, 126 HIGH,
     193 MEDIUM, 158 LOW, 9 UNKNOWN.
   - **Package groups, worst first**: libssl3t64, openssl and
     openssl-provider-legacy, 57 findings each, all CRITICAL.
3. Untick everything except **CRITICAL**: 4 groups remain, 6 findings.
   Tick everything again.
4. Click **+** next to **libssl3t64**: the list of its 57 CVEs, each with
   severity, status, fixed version, CVSS score and a link to the advisory.
   The AI explanation starts by itself ("Asking the AI… 5 s").
5. Show **Trivy's fix** in the row: the fixed versions straight from the
   report. This is always shown, with or without AI.
6. When the answer arrives (around 25 seconds), point out:
   - "AI suggestion: verify before applying" at the top.
   - The verdict is made by our code, not by the model. A version is shown
     as the recommended upgrade only if it is one of Trivy's fixed
     versions; any other version is marked as not a fix.
   - The commands are shown apart and are never run.
7. Close and open the group again: the answer is still there, with no
   second call to the LLM.

## 2. A source repository: fs.json

1. Choose `fs.json` and click **Analyze report**.
2. Point out:
   - **Report**: a git repository with its URL, branch `main` and commit.
     The git author and commit message are not shown and not kept.
   - **Counts**: 18 findings in 1 package: 10 HIGH, 7 MEDIUM, 1 LOW.
   - One group: **pypdf 6.19.0**, with 7 fixed versions from 6.20.0 to
     6.21.4.
3. Click **+** for pypdf: its AI explanation starts by itself.

## 3. When something goes wrong

1. Upload any file that is not JSON (for example an .html file): "only
   Trivy JSON reports are supported right now".
2. Change the base URL to `http://127.0.0.1:9`, click **Check
   connection** and open another group: one clear error, and Trivy's fix
   is still there. The app works without the LLM.
3. Type `https://ollama.com` as the base URL: the page warns which data
   would leave this computer.

## Talking points

- Deterministic code finds and groups the vulnerabilities; the LLM only
  explains. The LLM never decides what is vulnerable and never invents a
  version.
- Everything runs locally; nothing is saved.
- Next steps (Future scope in README.md): a database for upload history
  and tracking defects over time.
