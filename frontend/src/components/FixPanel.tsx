import { countText, KEEP_LINE_BREAKS, visibleText } from '../reportLogic'
import type { FixAdvice } from '../types'

export type FixState =
  | { state: 'loading' }
  | { state: 'done'; advice: FixAdvice }
  | { state: 'error'; message: string }

interface Props {
  fix: FixState | undefined // undefined: not asked yet
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

/**
 * "Explain with AI" for one group, and the checked answer. The live region
 * stays mounted in every state, so screen readers announce the answer.
 */
export function FixPanel({ fix, onExplain }: Props) {
  return (
    <div className="fix-panel" aria-live="polite">
      {fix?.state === 'done' ? (
        <Advice advice={fix.advice} />
      ) : (
        <>
          <button type="button" onClick={onExplain} disabled={fix?.state === 'loading'}>
            {fix?.state === 'loading' ? 'Asking the AI…' : 'Explain with AI'}
          </button>
          {fix?.state === 'error' && (
            <p className="form-error" role="alert">
              {visibleText(fix.message)} Trivy’s fix above is still valid.
            </p>
          )}
        </>
      )}
    </div>
  )
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
