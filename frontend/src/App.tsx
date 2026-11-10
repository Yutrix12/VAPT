import { useEffect, useMemo, useRef, useState } from 'react'
import { checkHealth, checkLlm, explainFix, type Health } from './api'
import { Filters } from './components/Filters'
import { GroupTable } from './components/GroupTable'
import { AiStatusPanel } from './components/AiStatusPanel'
import { ReportDetails } from './components/ReportDetails'
import { SeverityCounts } from './components/SeverityCounts'
import { UploadForm } from './components/UploadForm'
import { downloadText } from './download'
import { buildFixSummary, summaryFileName } from './fixSummary'
import { connectionFromStatus, serialQueue, toFixGroup } from './llmLogic'
import { ALL_STATUSES, filterGroups, groupKey, visibleText } from './reportLogic'
import {
  SEVERITIES,
  type AiConnection,
  type AnalyzeResult,
  type FixState,
  type PackageGroup,
  type Severity,
} from './types'
import './App.css'

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
        Drop a Trivy JSON report on the Report panel, or click it to choose one. You will see what was
        scanned, how severe the findings are, and how to fix each package.
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

  const shown = useMemo(
    () => (result ? filterGroups(result.package_groups, severities, status) : []),
    [result, severities, status],
  )

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
          <h1>Trivy report</h1>
          <p className="muted">Upload a scan and see what to fix first.</p>
          <HealthBadge health={health} />
        </header>
        <UploadForm onResult={showResult} />
        <AiStatusPanel connection={connection} onCheck={() => void checkConnection()} />
        {result && (
          <Filters
            severities={severities}
            onSeveritiesChange={setSeverities}
            counts={result.summary.by_severity}
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
            <SeverityCounts summary={result.summary} />
            <section aria-labelledby="groups-heading">
              <div className="section-head">
                <h2 id="groups-heading">Packages, worst first</h2>
                <div className="section-actions">
                  <p className="muted" aria-live="polite">
                    Showing {shown.length} of {result.package_groups.length}
                  </p>
                  <button type="button" className="secondary" onClick={downloadSummary}>
                    Download fix summary
                  </button>
                </div>
              </div>
              <GroupTable
                key={tableKey}
                shown={shown}
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
