import { useRef, useState } from 'react'
import { testLlm } from '../api'
import { isThisComputer } from '../llmLogic'
import { countText } from '../reportLogic'
import type { LlmSettings } from '../types'

interface Props {
  settings: LlmSettings
  onChange: (next: LlmSettings) => void
}

type TestState =
  | { state: 'idle' }
  | { state: 'testing' }
  | { state: 'done'; message: string; ok: boolean }

/**
 * Where Ollama is, which model, and an optional API key. Everything lives
 * in React state only: nothing is saved, and the key never goes in a URL.
 */
export function LlmSettingsPanel({ settings, onChange }: Props) {
  const [test, setTest] = useState<TestState>({ state: 'idle' })
  const [models, setModels] = useState<string[]>([])
  // Each edit makes earlier test answers outdated; this counts the edits.
  const settingsVersion = useRef(0)
  const leavesThisComputer = settings.baseUrl.trim() !== '' && !isThisComputer(settings.baseUrl.trim())

  function update(field: keyof LlmSettings, value: string) {
    settingsVersion.current += 1
    onChange({ ...settings, [field]: value })
    setTest({ state: 'idle' })
  }

  async function runTest() {
    const askedFor = settingsVersion.current
    setTest({ state: 'testing' })
    const result = await testLlm(settings)
    if (settingsVersion.current !== askedFor) return // the settings changed meanwhile
    if (!result.ok) {
      setTest({ state: 'done', ok: false, message: result.message })
      return
    }
    setModels(result.data.models)
    const model = settings.model.trim()
    let found = 'Pick a model from the list.'
    if (model) {
      found = result.data.model_found
        ? `"${model}" is available.`
        : `"${model}" is not among them: pick one from the list.`
    }
    setTest({
      state: 'done',
      ok: result.data.model_found || !model,
      message: `Connected: Ollama has ${countText(result.data.models.length, 'model')}. ${found}`,
    })
  }

  return (
    <section className="llm-settings" aria-labelledby="llm-heading">
      <h2 id="llm-heading">LLM settings</h2>
      <p className="muted">Only "Explain with AI" uses the LLM. Everything else works without it.</p>
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
            onChange={(event) => update('baseUrl', event.target.value)}
          />
        </label>
        <label>
          Model
          <input
            type="text"
            name="ollama-model"
            list="ollama-models"
            autoComplete="off"
            spellCheck={false}
            placeholder="e.g. llama3.2…"
            value={settings.model}
            onChange={(event) => update('model', event.target.value)}
          />
          <datalist id="ollama-models">
            {models.map((name) => (
              <option key={name} value={name} />
            ))}
          </datalist>
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
            onChange={(event) => update('apiKey', event.target.value)}
          />
        </label>
        <button type="button" onClick={runTest} disabled={test.state === 'testing'}>
          {test.state === 'testing' ? 'Testing…' : 'Test connection'}
        </button>
      </div>
      {leavesThisComputer && (
        <p className="notice">
          This address is not this computer. When you click "Explain with AI", this leaves the machine
          for that group: the package name and installed version, Trivy’s fixed versions, the
          ecosystem and OS, and up to 15 CVE IDs with severities and short titles.
        </p>
      )}
      <p className={test.state === 'done' && !test.ok ? 'form-error' : 'muted'} role="status" aria-live="polite">
        {test.state === 'done' ? test.message : ''}
      </p>
    </section>
  )
}
