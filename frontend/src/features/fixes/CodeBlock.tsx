import { useEffect, useRef, useState } from 'react'
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

  // Stop the pending "Copied" reset if the block goes away first.
  useEffect(() => () => clearTimeout(timer.current), [])

  async function copyText() {
    try {
      await navigator.clipboard.writeText(text)
      setCopy('copied')
    } catch {
      setCopy('failed') // no clipboard access (or refused): the text can still be selected
    }
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
          title={hidden ? 'This command has hidden characters, so it cannot be copied' : undefined}
          onClick={() => void copyText()}
        >
          {copy === 'copied' ? 'Copied' : copy === 'failed' ? 'Copy failed' : 'Copy'}
          <span className="visually-hidden"> {label ? visibleText(label) : 'command'}</span>
        </button>
      </div>
      <span className="visually-hidden" aria-live="polite">
        {copy === 'copied' ? 'Copied to the clipboard' : copy === 'failed' ? 'Could not copy' : ''}
      </span>
    </div>
  )
}
