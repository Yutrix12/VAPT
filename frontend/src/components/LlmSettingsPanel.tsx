import { AI_MODEL, isThisComputer } from '../llmLogic'
import { visibleText } from '../reportLogic'
import type { AiConnection, LlmSettings } from '../types'

interface Props {
  settings: LlmSettings
  onChange: (next: LlmSettings) => void
  connection: AiConnection
  onCheck: () => void
}

/** The line under the fields: is the AI ready, and if not, why. */
function connectionText(connection: AiConnection): string {
  switch (connection.state) {
    case 'checking':
      return 'Checking the connection…'
    case 'unchecked':
      return 'Settings changed: check the connection.'
    case 'ready':
      return `Connected: ${AI_MODEL} is ready.`
    case 'error':
      return connection.message
  }
}

/**
 * Where Ollama is and an optional API key; the model is always the same.
 * Everything lives in React state only: nothing is saved, and the key
 * never goes in a URL.
 */
export function LlmSettingsPanel({ settings, onChange, connection, onCheck }: Props) {
  const leavesThisComputer = settings.baseUrl.trim() !== '' && !isThisComputer(settings.baseUrl.trim())

  return (
    <section className="llm-settings" aria-labelledby="llm-heading">
      <h2 id="llm-heading">AI settings</h2>
      <p className="muted">
        Model: <span translate="no">{AI_MODEL}</span>. Opening a package asks it for an explanation; everything
        else works without it.
      </p>
      <div className="llm-fields">
        <label>
          Ollama base URL
          <input
            type="url"
            name="ollama-base-url"
            autoComplete="off"
            spellCheck={false}
            placeholder="http://localhost:11434"
            value={settings.baseUrl}
            onChange={(event) => onChange({ ...settings, baseUrl: event.target.value })}
          />
        </label>
        <label>
          API key (optional)
          <input
            type="password"
            name="ollama-api-key"
            // Browsers ignore "off" on password fields; "new-password"
            // discourages them from offering to save the key.
            autoComplete="new-password"
            spellCheck={false}
            placeholder="only for hosted Ollama…"
            value={settings.apiKey}
            onChange={(event) => onChange({ ...settings, apiKey: event.target.value })}
          />
        </label>
        <button type="button" onClick={onCheck} disabled={connection.state === 'checking'}>
          {connection.state === 'checking' ? 'Checking…' : 'Check connection'}
        </button>
      </div>
      {leavesThisComputer && (
        <p className="notice">
          This address is not this computer. Once it is connected, every package you open (and any that is
          open already) sends this to it: the package name and installed version, Trivy’s fixed versions,
          the ecosystem and OS, and up to 15 CVE IDs with severities and short titles.
        </p>
      )}
      <p className={connection.state === 'error' ? 'form-error' : 'muted'} role="status" aria-live="polite">
        {visibleText(connectionText(connection))}
      </p>
    </section>
  )
}
