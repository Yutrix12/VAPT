import { useEffect, useEffectEvent, useState } from 'react'
import type { AiConnection, AiState, FixAdvice, OtherAdvice } from '../../api/types'
import { KEEP_LINE_BREAKS, countText, visibleText } from '../../shared/text'
import { answerState, openAfterUpgradeText, otherAnswerState } from './fixLogic'

interface Props {
  fix: AiState<FixAdvice | OtherAdvice> | undefined // undefined: not asked yet
  connection: AiConnection
  onExplain: () => void
  fallback?: string // what still applies while there is no explanation
}

const TRIVY_FIX_STILL_APPLIES = 'Trivy’s fixed versions above still apply.'

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
export function FixPanel({ fix, connection, onExplain, fallback = TRIVY_FIX_STILL_APPLIES }: Props) {
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
      <FixContent fix={fix} connection={connection} needsClick={needsClick} onExplain={onExplain} fallback={fallback} />
    </div>
  )
}

function FixContent({ fix, connection, needsClick, onExplain, fallback }: Props & { needsClick: boolean; fallback: string }) {
  if (fix === undefined && needsClick) {
    return (
      <div>
        <p className="muted">
          The AI runs on a hosted service (see the notice under AI explanations). {fallback}
        </p>
        <button type="button" className="secondary" onClick={onExplain}>
          Send this finding to the hosted AI
        </button>
      </div>
    )
  }
  if (fix === undefined) {
    return <p className="muted">{visibleText(notReadyText(connection))} {fallback}</p>
  }
  switch (fix.state) {
    case 'queued':
      return (
        <p className="ai-wait">
          <span className="pulse is-still" aria-hidden="true" />
          <span>Waiting for the AI: it is explaining another finding first.</span>
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
          <p>{visibleText(fix.message)} {fallback}</p>
          <button type="button" className="secondary" onClick={onExplain} disabled={connection.state !== 'ready'}>
            Try again
          </button>
        </div>
      )
    case 'done':
      // Only the advice for the other kinds has a `kind`.
      return 'kind' in fix.advice ? <OtherAdviceView advice={fix.advice} /> : <Advice advice={fix.advice} />
  }
}

/** The checked AI answer: verdict first, AI text below, commands apart. */
function Advice({ advice }: { advice: FixAdvice }) {
  return (
    <>
      <p className="disclaimer">
        {visibleText(advice.disclaimer)}
      </p>
      <p className="answer-state">{answerState(advice.status)}</p>
      <VersionVerdict advice={advice} />
      {advice.cves_without_fix > 0 && (
        <p className="verdict verdict-warn">
          {openAfterUpgradeText(advice.cves_without_fix)}
        </p>
      )}
      <dl className="advice">
        <dt>Summary</dt>
        <dd>{visibleText(advice.summary, KEEP_LINE_BREAKS)}</dd>
        <Steps title="Solutions" steps={advice.solutions} ordered />
        <Steps title="Mitigations until a fix exists" steps={advice.mitigations} />
        <dt>Risks</dt>
        <dd>{visibleText(advice.risk_notes, KEEP_LINE_BREAKS)}</dd>
      </dl>
      {advice.unsafe_commands_removed > 0 && (
        <p className="muted">
          {countText(advice.unsafe_commands_removed, 'AI command')}{' '}
          {advice.unsafe_commands_removed === 1 ? 'was' : 'were'} not shown: it skips a safety check.
        </p>
      )}
      {advice.commands.length > 0 && (
        // Kept apart from the verdict: these come from the AI and are untrusted.
        <div className="commands">
          <p className="commands-heading">
            AI-suggested, verify before running. This page only shows these commands; it never runs them.
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

/** A list of steps from the AI (solutions or mitigations). */
function Steps({ title, steps, ordered = false }: { title: string; steps: string[]; ordered?: boolean }) {
  if (steps.length === 0) return null
  const items = steps.map((text, index) => <li key={`${index}-${text}`}>{visibleText(text, KEEP_LINE_BREAKS)}</li>)
  return (
    <>
      <dt>{title}</dt>
      <dd>{ordered ? <ol className="steps">{items}</ol> : <ul className="steps">{items}</ul>}</dd>
    </>
  )
}

/** The checked AI advice for a misconfiguration, a secret or a license. */
function OtherAdviceView({ advice }: { advice: OtherAdvice }) {
  return (
    <>
      <p className="disclaimer">{visibleText(advice.disclaimer)}</p>
      <p className="answer-state">{otherAnswerState(advice.status)}</p>
      <dl className="advice">
        <dt>Summary</dt>
        <dd>{visibleText(advice.summary, KEEP_LINE_BREAKS)}</dd>
        <Steps title="Solutions" steps={advice.solutions} ordered />
        <Steps title="Mitigations until it is fixed" steps={advice.mitigations} />
        <dt>Risks</dt>
        <dd>{visibleText(advice.risk_notes, KEEP_LINE_BREAKS)}</dd>
      </dl>
    </>
  )
}
