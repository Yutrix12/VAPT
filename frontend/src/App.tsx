import { useEffect, useMemo, useState } from 'react'
import { checkHealth, type Health } from './api'
import { Filters } from './components/Filters'
import { GroupTable } from './components/GroupTable'
import { ReportDetails } from './components/ReportDetails'
import { SeverityCounts } from './components/SeverityCounts'
import { UploadForm } from './components/UploadForm'
import { filterGroups } from './reportLogic'
import { SEVERITIES, type AnalyzeResult, type Severity } from './types'
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
  }

  return (
    <main className="page">
      <h1>Trivy report prototype</h1>
      <p className="lead">Upload a Trivy JSON report to see its vulnerabilities and how to fix them.</p>
      <p className="status" aria-live="polite">
        <HealthBadge health={health} />
      </p>
      <UploadForm onResult={showResult} />
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
            <GroupTable shown={shown} />
          </section>
        </>
      )}
    </main>
  )
}

export default App
