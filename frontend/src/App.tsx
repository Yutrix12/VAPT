import { useEffect, useMemo, useRef, useState } from 'react'
import { checkHealth, explainFix, type Health } from './api'
import { Filters } from './components/Filters'
import type { FixState } from './components/FixPanel'
import { GroupTable } from './components/GroupTable'
import { LlmSettingsPanel } from './components/LlmSettingsPanel'
import { ReportDetails } from './components/ReportDetails'
import { SeverityCounts } from './components/SeverityCounts'
import { UploadForm } from './components/UploadForm'
import { DEFAULT_BASE_URL, fixCacheKey, toFixGroup } from './llmLogic'
import { filterGroups } from './reportLogic'
import { SEVERITIES, type AnalyzeResult, type LlmSettings, type PackageGroup, type Severity } from './types'
import './App.css'

function HealthBadge({ health }: { health: Health }) {
  if (health.state === 'checking') return <span className="badge">Checking the backend…</span>
  if (health.state === 'ok') return <span className="badge badge-ok">Ready: backend is running</span>
  return <span className="badge badge-error">Not ready: {health.message}</span>
}

function App() {
  const [health, setHealth] = useState<Health>({ state: 'checking' })
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [severities, setSeverities] = useState<Set<Severity>>(() => new Set(SEVERITIES))
  const [status, setStatus] = useState('all')
  const [llm, setLlm] = useState<LlmSettings>({ baseUrl: DEFAULT_BASE_URL, model: '', apiKey: '' })
  // AI answers per group and model, in React state only (gone on reload).
  const [fixes, setFixes] = useState<ReadonlyMap<string, FixState>>(new Map())
  // Requests on their way right now, so a quick second click never calls the
  // LLM again, even before React has re-rendered.
  const inFlight = useRef(new Set<string>())
  // Counts loaded reports, so a late answer for an earlier report is dropped.
  const reportNumber = useRef(0)

  useEffect(() => {
    // Ignore a late answer if the component is gone (React StrictMode mounts twice).
    let active = true
    void checkHealth().then((next) => {
      if (active) setHealth(next)
    })
    return () => {
      active = false
    }
  }, [])

  const shown = useMemo(
    () => (result ? filterGroups(result.package_groups, severities, status) : []),
    [result, severities, status],
  )

  function showResult(next: AnalyzeResult) {
    setResult(next)
    setSeverities(new Set(SEVERITIES))
    setStatus('all')
    // A new report starts without AI answers: an old answer could belong
    // to a group whose fixed versions have changed.
    reportNumber.current += 1
    inFlight.current.clear()
    setFixes(new Map())
  }

  function setFix(key: string, fix: FixState) {
    setFixes((current) => new Map(current).set(key, fix))
  }

  async function explain(group: PackageGroup) {
    if (result === null) return
    const key = fixCacheKey(group, llm)
    // Already answered or on its way: no second call to the LLM.
    if (inFlight.current.has(key) || fixes.get(key)?.state === 'done') return
    inFlight.current.add(key)
    const askedFor = reportNumber.current
    setFix(key, { state: 'loading' })
    const answer = await explainFix(llm, toFixGroup(group, result.report))
    if (reportNumber.current !== askedFor) return // a newer report is shown now
    inFlight.current.delete(key)
    setFix(key, answer.ok ? { state: 'done', advice: answer.data } : { state: 'error', message: answer.message })
  }

  return (
    <main className="page">
      <h1>Trivy report prototype</h1>
      <p className="lead">Upload a Trivy JSON report to see its vulnerabilities and how to fix them.</p>
      <p className="status" aria-live="polite">
        <HealthBadge health={health} />
      </p>
      <UploadForm onResult={showResult} />
      <LlmSettingsPanel settings={llm} onChange={setLlm} />
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
              shown={shown}
              fixFor={(group) => fixes.get(fixCacheKey(group, llm))}
              onExplain={(group) => void explain(group)}
            />
          </section>
        </>
      )}
    </main>
  )
}

export default App
