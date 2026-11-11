import { useEffect, useId, useRef, useState } from 'react'
import { KEEP_LINE_BREAKS, hasHiddenCharacters, visibleText } from '../../shared/text'

type CopyState = 'idle' | 'copied' | 'failed'

/**
 * A command in a light block with a Copy button. The Copy button is off when
 * the command holds hidden characters: what you would paste would then differ
 * from what you see.
 */
export function CodeBlock({ text, label }: { text: string; label?: string | null }) {
  const [copy, setCopy] = useState<CopyState>('idle')
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const hidden = hasHiddenCharacters(text)
  const hintId = useId()
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true // StrictMode runs the cleanup once before the real mount
    return () => {
      mounted.current = false
      clearTimeout(timer.current) // stop the pending "Copied" reset if the block goes away first
    }
  }, [])

  async function copyText() {
    let next: CopyState = 'copied'
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      next = 'failed' // no clipboard access (or refused): the text can still be selected
    }
    if (!mounted.current) return // the block went away while the clipboard answered
    setCopy(next)
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setCopy('idle'), 2000)
  }

  return (
    <div className="code-block">
      {label && <p className="code-label">{visibleText(label)}</p>}
      <div className="code-body">
        <pre translate="no">
          <code>{visibleText(text, KEEP_LINE_BREAKS)}</code>
        </pre>
        <button
          type="button"
          className="secondary copy-button"
          disabled={hidden}
          aria-describedby={hidden ? hintId : undefined}
          onClick={() => void copyText()}
        >
          {copy === 'copied' ? 'Copied' : copy === 'failed' ? 'Copy failed' : 'Copy'}
          <span className="visually-hidden"> {label ? visibleText(label) : 'command'}</span>
        </button>
      </div>
      {hidden && (
        <p id={hintId} className="muted code-hint">
          Copy is off: this command has hidden characters, so what you would paste differs from what you see.
        </p>
      )}
      <span className="visually-hidden" aria-live="polite">
        {copy === 'copied' ? 'Copied to the clipboard' : copy === 'failed' ? 'Could not copy' : ''}
      </span>
    </div>
  )
}
