import { useId, useState } from 'react'
import type { BuiltCommand } from '../../api/types'
import { visibleText } from '../../shared/text'
import { CodeBlock } from './CodeBlock'

interface Props {
  commands: BuiltCommand[] // built by code from Trivy's fixed version
  note: string | null // why there is no command, or what to know about the ones shown
}

/** The upgrade commands the backend built from Trivy's fixed versions, behind a "Show fix code" button. */
export function FixCommands({ commands, note }: Props) {
  const [shown, setShown] = useState(false)
  const bodyId = useId()
  return (
    <section className="fix-code" aria-label="Fix commands built by code">
      <button
        type="button"
        className="secondary"
        aria-expanded={shown}
        aria-controls={shown ? bodyId : undefined}
        onClick={() => setShown((current) => !current)}
      >
        {shown ? 'Hide fix code' : 'Show fix code'}
      </button>
      {shown && (
        <div id={bodyId} className="fix-code-body">
          {commands.map((command, index) => (
            <CodeBlock key={`${index}-${command.label ?? ''}`} label={command.label} text={command.lines.join('\n')} />
          ))}
          {commands.length === 0 && note === null && <p className="muted">The report gives no fix command.</p>}
          {note !== null && <p className="muted">{visibleText(note)}</p>}
          {commands.length > 0 && (
            <p className="muted">
              Built by code from Trivy’s fixed version, with syntax from the package manager’s documentation. This
              page only shows commands; it never runs them.
            </p>
          )}
        </div>
      )}
    </section>
  )
}
