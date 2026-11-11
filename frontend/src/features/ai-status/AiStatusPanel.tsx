import type { AiConnection } from '../../api/types'
import { visibleText } from '../../shared/text'

interface Props {
  connection: AiConnection
  onCheck: () => void
}

/** The line under the heading: is the AI ready, and if not, why. */
function connectionText(connection: AiConnection): string {
  switch (connection.state) {
    case 'checking':
      return 'Checking the connection…'
    case 'ready':
      return `Connected: ${connection.model} is ready.`
    case 'error':
      return connection.message
  }
}

const TONES: Record<AiConnection['state'], string> = {
  checking: 'busy',
  ready: 'ok',
  error: 'error',
}

/**
 * Whether the AI explanations work. The backend chooses the LLM (see
 * backend/llm_config.py); the page has no settings and never sees a key.
 */
export function AiStatusPanel({ connection, onCheck }: Props) {
  return (
    <section className="panel" aria-labelledby="ai-heading">
      <h2 id="ai-heading" className="panel-title">
        AI explanations
      </h2>
      <p className={`status-line status-${TONES[connection.state]}`} role="status" aria-live="polite">
        <span className="dot" aria-hidden="true" />
        <span>{visibleText(connectionText(connection))}</span>
      </p>
      {connection.state === 'error' && <p className="hint">Fix this, then click Check connection.</p>}
      <p className="hint">
        Opening a package asks the AI to explain how to fix it. The rest of the page works without the AI.
      </p>
      {connection.state === 'ready' && connection.leavesThisComputer && (
        <p className="notice">
          The AI runs on a hosted service, not on this computer. Every package you open sends this to it:
          the package name and installed version, Trivy’s fixed versions, the ecosystem and OS, up to 15
          vulnerability IDs with their severity, fixed version and a short title, and how many vulnerabilities
          are not listed or have no fixed version.
        </p>
      )}
      <button type="button" className="secondary wide" onClick={onCheck} disabled={connection.state === 'checking'}>
        {connection.state === 'checking' ? 'Checking…' : 'Check connection'}
      </button>
    </section>
  )
}
