import { useEffect, useMemo, useRef, useState } from 'react'
import { checkHealth, checkLlm, explainFix, type Health } from './api/client'
import {
  SEVERITIES,
  type AiConnection,
  type AnalyzeResult,
  type FixState,
  type Kind,
  type PackageGroup,
  type Severity,
} from './api/types'
import { AiStatusPanel } from './features/ai-status/AiStatusPanel'
import { connectionFromStatus } from './features/ai-status/connection'
import { ALL_STATUSES } from './features/filters/filterGroups'
import { Filters } from './features/filters/Filters'
import { serialQueue, toFixGroup } from './features/fixes/fixLogic'
import { buildFixSummary, summaryFileName } from './features/fixes/fixSummary'
import { FindingsTable } from './features/report/FindingsTable'
import { groupKey } from './features/report/groupKey'
import { ReportDetails } from './features/report/ReportDetails'
import { buildRows, severityCounts } from './features/report/rows'
import { SeverityCounts } from './features/report/SeverityCounts'
import { UploadForm } from './features/upload/UploadForm'
import { downloadText } from './shared/download'
import { overviewText, shownText } from './shared/reportText'
import { visibleText } from './shared/text'
import './App.css'

/** The rows the table has before any filter: one per package, plus one per other finding. */
function totalRows(result: AnalyzeResult): number {
  return result.package_groups.length + result.misconfigurations.length + result.secrets.length + result.licenses.length
}

/** A small status line with a coloured dot; the words carry the meaning. */
function HealthBadge({ health }: { health: Health }) {
  const tone = health.state === 'ok' ? 'ok' : health.state === 'error' ? 'error' : 'busy'
  const text =
    health.state === 'checking'
      ? 'Checking the backend…'
      : health.state === 'ok'
        ? 'Backend running'
        : `Backend not ready: ${visibleText(health.message)}`
  return (
    <p className={`status-line status-${tone}`} aria-live="polite">
      <span className="dot" aria-hidden="true" />
      {text}
    </p>
  )
}

/** What the main area shows before the first report. */
function EmptyState() {
  return (
    <section className="empty" aria-labelledby="empty-heading">
      <h2 id="empty-heading">No report yet</h2>
      <p>
        Drop a Trivy report on <strong>Upload a report</strong>, or click it to choose a file. You’ll see
        what was scanned, how severe each finding is, and how to fix it.
      </p>
    </section>
  )
}

function App() {
  const [health, setHealth] = useState<Health>({ state: 'checking' })
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [severities, setSeverities] = useState<Set<Severity>>(() => new Set(SEVERITIES))
  const [status, setStatus] = useState(ALL_STATUSES)
  const [connection, setConnection] = useState<AiConnection>({ state: 'checking' })
  // The model of the last successful check: answers are kept per model, so
  // a backend switched to another model never shows an older model's advice.
  const [aiModel, setAiModel] = useState<string | null>(null)
  // One AI request at a time; the lazy initializer makes one queue for the app's lifetime.
  const [enqueue] = useState(() => serialQueue())
  // AI answers per group and model, in React state only (gone on reload).
  const [fixes, setFixes] = useState<ReadonlyMap<string, FixState>>(new Map())
  // Requests on their way right now, so a quick second click never calls the
  // LLM again, even before React has re-rendered.
  const inFlight = useRef(new Set<string>())
  // Counts loaded reports, so a late answer for an earlier report is dropped.
  const reportNumber = useRef(0)
  // The same count for rendering: a new report gets a fresh table, so no
  // group stays open (and asks the AI) from the previous report.
  const [tableKey, setTableKey] = useState(0)

  function applyCheck(next: AiConnection) {
    setConnection(next)
    if (next.state === 'ready') setAiModel(next.model)
  }

  useEffect(() => {
    // Ignore a late answer if the component is gone (React StrictMode mounts twice).
    let active = true
    void checkHealth().then((next) => {
      if (active) setHealth(next)
    })
    // Check the AI once at the start, so opening a package can explain it.
    void checkLlm().then((result) => {
      if (active) applyCheck(connectionFromStatus(result))
    })
    return () => {
      active = false
    }
  }, [])

  // The button is disabled while a check runs, so two checks never overlap.
  async function checkConnection() {
    setConnection({ state: 'checking' })
    applyCheck(connectionFromStatus(await checkLlm()))
  }

  function fixKey(group: PackageGroup): string {
    return JSON.stringify([groupKey(group), aiModel])
  }

  // One lookup for the table and the fix summary, so both always agree.
  function fixFor(group: PackageGroup): FixState | undefined {
    return fixes.get(fixKey(group))
  }

  const rows = useMemo(() => (result ? buildRows(result, severities, status) : []), [result, severities, status])
  // The fix summary lists vulnerabilities only until U9 adds the other kinds.
  const shown = useMemo(() => rows.flatMap((row) => (row.kind === 'vulnerability' ? [row.shown] : [])), [rows])
  const counts = useMemo(() => (result ? severityCounts(result) : null), [result])

  function showResult(next: AnalyzeResult) {
    setResult(next)
    setSeverities(new Set(SEVERITIES))
    setStatus(ALL_STATUSES)
    // A new report starts without AI answers: an old answer could belong
    // to a group whose fixed versions have changed.
    reportNumber.current += 1
    setTableKey(reportNumber.current)
    inFlight.current.clear()
    setFixes(new Map())
  }

  function setFix(key: string, fix: FixState) {
    setFixes((current) => new Map(current).set(key, fix))
  }

  /** The fix summary of what the page shows now, as a Markdown file. */
  function downloadSummary() {
    if (result === null) return
    const text = buildFixSummary({
      result,
      shown,
      severities,
      status,
      fixFor,
      model: aiModel,
    })
    downloadText(summaryFileName(result.report.file_name), text, 'text/markdown;charset=utf-8')
  }

  function explain(group: PackageGroup) {
    if (result === null) return
    const key = fixKey(group)
    // Already answered or on its way: no second call to the LLM.
    if (inFlight.current.has(key) || fixes.get(key)?.state === 'done') return
    inFlight.current.add(key)
    const askedFor = reportNumber.current
    const body = toFixGroup(group, result.report)
    setFix(key, { state: 'queued' })
    void enqueue(async () => {
      if (reportNumber.current !== askedFor) return // a newer report is shown now
      setFix(key, { state: 'loading', startedAt: Date.now() })
      const answer = await explainFix(body)
      if (reportNumber.current !== askedFor) return
      inFlight.current.delete(key)
      setFix(key, answer.ok ? { state: 'done', advice: answer.data } : { state: 'error', message: answer.message })
    })
  }

  return (
    <div className="shell">
      <a className="skip-link" href="#results">
        Skip to results
      </a>
      <aside className="sidebar">
        <header className="brand">
          <h1>Trivy report viewer</h1>
          <p className="muted">Upload a Trivy report to see what to fix first.</p>
          <HealthBadge health={health} />
        </header>
        <UploadForm onResult={showResult} />
        <AiStatusPanel connection={connection} onCheck={() => void checkConnection()} />
        {result && (
          <Filters
            severities={severities}
            onSeveritiesChange={setSeverities}
            counts={counts ?? result.summary.by_severity}
            status={status}
            statuses={Object.keys(result.summary.by_status)}
            onStatusChange={setStatus}
          />
        )}
      </aside>
      <main className="main" id="results">
        {result ? (
          <>
            <ReportDetails report={result.report} />
            <SeverityCounts
              summary={result.summary}
              counts={counts ?? result.summary.by_severity}
              headline={overviewText(result.summary.by_kind as Record<Kind, number>, result.summary.unique_packages)}
            />
            <section aria-labelledby="groups-heading">
              <div className="section-head">
                <h2 id="groups-heading">Findings by severity</h2>
                <div className="section-actions">
                  <p className="muted" aria-live="polite">
                    {shownText(rows.length, totalRows(result))}
                  </p>
                  <button type="button" className="secondary" onClick={downloadSummary}>
                    Download fix summary
                  </button>
                </div>
              </div>
              <FindingsTable
                key={tableKey}
                rows={rows}
                notInFormat={result.report.not_in_format}
                secretFixSteps={result.secret_fix_steps}
                connection={connection}
                fixFor={fixFor}
                onExplain={explain}
              />
            </section>
          </>
        ) : (
          <EmptyState />
        )}
      </main>
    </div>
  )
}

export default App
