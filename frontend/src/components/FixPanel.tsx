import { useEffect, useEffectEvent, useState } from 'react'
import type { AiConnection, FixAdvice, FixState } from '../api/types'
import { KEEP_LINE_BREAKS, openAfterUpgradeText, visibleText } from '../reportLogic'

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
          is not one of Trivy’s fixed versions, so it is not shown as a fix. Use one of Trivy’s fixed versions above.
        </p>
      )
    case 'no_version_suggested':
      return <p className="verdict">The AI named no version. Use one of Trivy’s fixed versions above.</p>
    case 'no_fix_available':
      return (
        <p className="verdict verdict-warn">
          Trivy lists no fixed version yet. The advice below covers mitigations only.
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
  // With a hosted AI the notice must be on screen before data is sent: a
  // package opened before the AI was ready waits for a click instead.
  const [openedWhileReady] = useState(connection.state === 'ready')
  const needsClick = connection.state === 'ready' && connection.leavesThisComputer && !openedWhileReady
  const shouldAsk = fix === undefined && connection.state === 'ready' && !needsClick
  // Calls the latest onExplain without making the effect depend on it.
  const ask = useEffectEvent(onExplain)
  useEffect(() => {
    // App ignores a second call for the same group (StrictMode runs this twice).
    if (shouldAsk) ask()
  }, [shouldAsk])

  return (
    <div className="fix-panel" aria-live="polite">
      <FixContent fix={fix} connection={connection} needsClick={needsClick} onExplain={onExplain} />
    </div>
  )
}

function FixContent({ fix, connection, needsClick, onExplain }: Props & { needsClick: boolean }) {
  if (fix === undefined && needsClick) {
    return (
      <div>
        <p className="muted">
          The AI runs on a hosted service (see the notice under AI explanations). Trivy’s fixed versions
          above still apply.
        </p>
        <button type="button" className="secondary" onClick={onExplain}>
          Send this package to the hosted AI
        </button>
      </div>
    )
  }
  if (fix === undefined) {
    return <p className="muted">{visibleText(notReadyText(connection))} Trivy’s fixed versions above still apply.</p>
  }
  switch (fix.state) {
    case 'queued':
      return (
        <p className="ai-wait">
          <span className="pulse is-still" aria-hidden="true" />
          <span>Waiting for the AI: it is explaining another package first.</span>
        </p>
      )
    case 'loading':
      return (
        <p className="ai-wait">
          <span className="pulse" aria-hidden="true" />
          <span>
            Asking the AI… <Elapsed since={fix.startedAt} />
          </span>
        </p>
      )
    case 'error':
      return (
        <div className="ai-error" role="alert">
          <p>{visibleText(fix.message)} Trivy’s fixed versions above still apply.</p>
          <button type="button" className="secondary" onClick={onExplain} disabled={connection.state !== 'ready'}>
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
      <p className="disclaimer">
        {visibleText(advice.disclaimer)}
      </p>
      <VersionVerdict advice={advice} />
      {advice.cves_without_fix > 0 && (
        <p className="verdict verdict-warn">
          {openAfterUpgradeText(advice.cves_without_fix)}
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
            AI-suggested commands: verify before running. This page only shows them; it never runs them.
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
