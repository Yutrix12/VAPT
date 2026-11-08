import { useEffect, useMemo, useRef, useState } from 'react'
import { checkHealth, explainFix, testLlm, type Health } from './api'
import { Filters } from './components/Filters'
import type { FixState } from './components/FixPanel'
import { GroupTable } from './components/GroupTable'
import { LlmSettingsPanel } from './components/LlmSettingsPanel'
import { ReportDetails } from './components/ReportDetails'
import { SeverityCounts } from './components/SeverityCounts'
import { UploadForm } from './components/UploadForm'
import { connectionFromTest, DEFAULT_BASE_URL, fixCacheKey, serialQueue, toFixGroup } from './llmLogic'
import { ALL_STATUSES, filterGroups, visibleText } from './reportLogic'
import {
  SEVERITIES,
  type AiConnection,
  type AnalyzeResult,
  type LlmSettings,
  type PackageGroup,
  type Severity,
} from './types'
import './App.css'

function HealthBadge({ health }: { health: Health }) {
  if (health.state === 'checking') return <span className="badge">Checking the backend…</span>
  if (health.state === 'ok') return <span className="badge badge-ok">Ready: backend is running</span>
  return <span className="badge badge-error">Not ready: {visibleText(health.message)}</span>
}

const INITIAL_SETTINGS: LlmSettings = { baseUrl: DEFAULT_BASE_URL, apiKey: '' }

function App() {
  const [health, setHealth] = useState<Health>({ state: 'checking' })
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [severities, setSeverities] = useState<Set<Severity>>(() => new Set(SEVERITIES))
  const [status, setStatus] = useState(ALL_STATUSES)
  const [llm, setLlm] = useState(INITIAL_SETTINGS)
  const [connection, setConnection] = useState<AiConnection>({ state: 'checking' })
  // Each settings edit makes earlier connection checks outdated; this counts the edits.
  const settingsVersion = useRef(0)
  // One AI request at a time; the lazy initializer makes one queue for the app's lifetime.
  const [enqueue] = useState(() => serialQueue())
  // AI answers per group and Ollama address, in React state only (gone on reload).
  const [fixes, setFixes] = useState<ReadonlyMap<string, FixState>>(new Map())
  // Requests on their way right now, so a quick second click never calls the
  // LLM again, even before React has re-rendered.
  const inFlight = useRef(new Set<string>())
  // Counts loaded reports, so a late answer for an earlier report is dropped.
  const reportNumber = useRef(0)
  // The same count for rendering: a new report gets a fresh table, so no
  // group stays open (and asks the AI) from the previous report.
  const [tableKey, setTableKey] = useState(0)

  useEffect(() => {
    // Ignore a late answer if the component is gone (React StrictMode mounts twice).
    let active = true
    void checkHealth().then((next) => {
      if (active) setHealth(next)
    })
    // Check the AI once at the start, so opening a package can explain it.
    // Its answer is dropped if the settings were edited meanwhile.
    void testLlm(INITIAL_SETTINGS).then((result) => {
      if (active && settingsVersion.current === 0) setConnection(connectionFromTest(result))
    })
    return () => {
      active = false
    }
  }, [])

  function changeSettings(next: LlmSettings) {
    settingsVersion.current += 1
    setLlm(next)
    setConnection({ state: 'unchecked' })
  }

  async function checkConnection() {
    const askedFor = settingsVersion.current
    setConnection({ state: 'checking' })
    const result = await testLlm(llm)
    if (settingsVersion.current === askedFor) setConnection(connectionFromTest(result))
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

  function explain(group: PackageGroup) {
    if (result === null) return
    const key = fixCacheKey(group, llm)
    // Already answered or on its way: no second call to the LLM.
    if (inFlight.current.has(key) || fixes.get(key)?.state === 'done') return
    inFlight.current.add(key)
    const askedFor = reportNumber.current
    const settingsWhenAsked = settingsVersion.current
    const settings = llm
    const body = toFixGroup(group, result.report)
    setFix(key, { state: 'queued' })
    void enqueue(async () => {
      if (reportNumber.current !== askedFor) return // a newer report is shown now
      if (settingsVersion.current !== settingsWhenAsked) {
        // The address or key changed while waiting: never send to the old one.
        inFlight.current.delete(key)
        setFixes((current) => {
          const next = new Map(current)
          next.delete(key)
          return next
        })
        return
      }
      setFix(key, { state: 'loading', startedAt: Date.now() })
      const answer = await explainFix(settings, body)
      if (reportNumber.current !== askedFor) return
      inFlight.current.delete(key)
      setFix(key, answer.ok ? { state: 'done', advice: answer.data } : { state: 'error', message: answer.message })
    })
  }

  return (
    <main className="page">
      <h1>Trivy report prototype</h1>
      <p className="lead">Upload a Trivy JSON report to see its vulnerabilities and how to fix them.</p>
      <p className="status" aria-live="polite">
        <HealthBadge health={health} />
      </p>
      <UploadForm onResult={showResult} />
      <LlmSettingsPanel
        settings={llm}
        onChange={changeSettings}
        connection={connection}
        onCheck={() => void checkConnection()}
      />
      {result && (
        <>
          <ReportDetails report={result.report} />
          <SeverityCounts summary={result.summary} />
          <section aria-labelledby="groups-heading">
            <h2 id="groups-heading">Packages, worst first</h2>
            <Filters
              severities={severities}
              onSeveritiesChange={setSeverities}
              status={status}
              statuses={Object.keys(result.summary.by_status)}
              onStatusChange={setStatus}
            />
            <p className="muted" aria-live="polite">
              Showing {shown.length} of {result.package_groups.length} package groups.
            </p>
            <GroupTable
              key={tableKey}
              shown={shown}
              connection={connection}
              fixFor={(group) => fixes.get(fixCacheKey(group, llm))}
              onExplain={explain}
            />
          </section>
        </>
      )}
    </main>
  )
}

export default App
