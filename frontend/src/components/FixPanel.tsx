import { useEffect, useEffectEvent, useState } from 'react'
import { AI_MODEL } from '../llmLogic'
import { countText, KEEP_LINE_BREAKS, visibleText } from '../reportLogic'
import type { AiConnection, FixAdvice } from '../types'

export type FixState =
  | { state: 'queued' } // waiting while another explanation runs
  | { state: 'loading'; startedAt: number }
  | { state: 'done'; advice: FixAdvice }
  | { state: 'error'; message: string }

interface Props {
  fix: FixState | undefined // undefined: not asked yet
  connection: AiConnection
  onExplain: () => void
}

/** What the code decided about the AI's version. The model never decides this. */
function VersionVerdict({ advice }: { advice: FixAdvice }) {
  switch (advice.status) {
    case 'verified':
      return (
        <p className="verdict verdict-ok">
          Recommended upgrade: <span translate="no" className="nowrap">{visibleText(advice.target_version ?? '')}</span>{' '}
          (one of Trivy’s fixed versions).
        </p>
      )
    case 'unverified':
      return (
        <p className="verdict verdict-warn">
          The AI suggested <span translate="no" className="nowrap">{visibleText(advice.unverified_version ?? '')}</span>, which
          is not one of Trivy’s fixed versions, so it is not shown as a fix. Use Trivy’s fix above.
        </p>
      )
    case 'no_version_suggested':
      return <p className="verdict">The AI named no version. Use Trivy’s fix above.</p>
    case 'no_fix_available':
      return (
        <p className="verdict verdict-warn">
          No fix available yet. The advice below is about mitigations only.
        </p>
      )
  }
}

/** Seconds since `since`, updated every second while shown. */
function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])
  // Hidden from screen readers: the live region would announce every second.
  return (
    <span className="elapsed" aria-hidden="true">
      {Math.max(0, Math.round((now - since) / 1000))} s
    </span>
  )
}

/** Why there is no explanation yet, when the AI is not ready. */
function notReadyText(connection: AiConnection): string {
  switch (connection.state) {
    case 'checking':
      return 'Connecting to the AI…'
    case 'unchecked':
      return 'The AI settings changed: check the connection to get an explanation.'
    case 'error':
      return `No AI explanation: ${connection.message}`
    case 'ready':
      return 'Asking the AI…'
  }
}

/**
 * The AI explanation for one open group. It starts by itself once the AI
 * is ready; answers are cached, so each group is asked once. The live
 * region stays mounted in every state, so screen readers announce changes.
 */
export function FixPanel({ fix, connection, onExplain }: Props) {
  const shouldAsk = fix === undefined && connection.state === 'ready'
  // Calls the latest onExplain without making the effect depend on it.
  const ask = useEffectEvent(onExplain)
  useEffect(() => {
    // App ignores a second call for the same group (StrictMode runs this twice).
    if (shouldAsk) ask()
  }, [shouldAsk])

  return (
    <div className="fix-panel" aria-live="polite">
      <FixContent fix={fix} connection={connection} onExplain={onExplain} />
    </div>
  )
}

function FixContent({ fix, connection, onExplain }: Props) {
  if (fix === undefined) return <p className="muted">{visibleText(notReadyText(connection))} Trivy’s fix above still applies.</p>
  switch (fix.state) {
    case 'queued':
      return <p className="muted">Waiting for the AI: it is explaining another package first.</p>
    case 'loading':
      return (
        <p className="muted">
          Asking the AI ({AI_MODEL})… <Elapsed since={fix.startedAt} />
        </p>
      )
    case 'error':
      return (
        <div className="form-error" role="alert">
          <p>{visibleText(fix.message)} Trivy’s fix above is still valid.</p>
          <button type="button" onClick={onExplain} disabled={connection.state !== 'ready'}>
            Try again
          </button>
        </div>
      )
    case 'done':
      return <Advice advice={fix.advice} />
  }
}

/** The checked AI answer: verdict first, AI text below, commands apart. */
function Advice({ advice }: { advice: FixAdvice }) {
  return (
    <>
      <p className="disclaimer">{visibleText(advice.disclaimer)}</p>
      <VersionVerdict advice={advice} />
      {advice.cves_without_fix > 0 && (
        <p className="verdict verdict-warn">
          {countText(advice.cves_without_fix, 'CVE')} in this group {advice.cves_without_fix === 1 ? 'has' : 'have'} no
          fix yet and {advice.cves_without_fix === 1 ? 'stays' : 'stay'} open after any upgrade.
        </p>
      )}
      <dl className="advice">
        <dt>Summary</dt>
        <dd>{visibleText(advice.summary, KEEP_LINE_BREAKS)}</dd>
        <dt>{advice.mitigation_only ? 'Mitigation' : 'What to do'}</dt>
        <dd>{visibleText(advice.recommended_action, KEEP_LINE_BREAKS)}</dd>
        <dt>Risks</dt>
        <dd>{visibleText(advice.risk_notes, KEEP_LINE_BREAKS)}</dd>
      </dl>
      {advice.commands.length > 0 && (
        // Kept apart from the verdict: these come from the AI and are untrusted.
        <div className="commands">
          <p className="commands-heading">
            Suggested commands (AI). They are only shown, never run: check each one before you use it.
          </p>
          {advice.commands.map((command, index) => (
            <pre key={index} translate="no">
              <code>{visibleText(command, KEEP_LINE_BREAKS)}</code>
            </pre>
          ))}
        </div>
      )}
    </>
  )
}
