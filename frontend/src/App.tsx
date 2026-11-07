import { useEffect, useState } from 'react'
import { checkHealth, type Health } from './api'
import './App.css'

function App() {
  const [health, setHealth] = useState<Health>({ state: 'checking' })

  useEffect(() => {
    // Ignore a late answer if the component is gone (React StrictMode mounts twice).
    let active = true
    void checkHealth().then((result) => {
      if (active) setHealth(result)
    })
    return () => {
      active = false
    }
  }, [])

  return (
    <main className="page">
      <h1>Trivy report prototype</h1>
      <p className="lead">Upload a Trivy JSON report to see its vulnerabilities and how to fix them.</p>
      <p className="status" aria-live="polite">
        {health.state === 'checking' && <span className="badge">Checking the backend…</span>}
        {health.state === 'ok' && <span className="badge badge-ok">Ready: backend is running</span>}
        {health.state === 'error' && <span className="badge badge-error">Not ready: {health.message}</span>}
      </p>
    </main>
  )
}

export default App
