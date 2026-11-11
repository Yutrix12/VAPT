import { useEffect, useId, useRef, type ReactNode } from 'react'
import { visibleText } from '../../shared/text'

interface Props {
  title: string // the item, e.g. a package name
  subtitle: ReactNode // its kind and severity
  onClose: () => void // called once the dialog has closed, whatever closed it
  children: ReactNode
}

/**
 * The details of one finding in a modal dialog. The browser's own <dialog>
 * gives Esc to close, the dimmed backdrop, a focus that stays inside while
 * it is open, and the focus back on the button that opened it.
 */
export function DetailsDialog({ title, subtitle, onClose, children }: Props) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  // True while a press that began on the backdrop is going on: a drag that starts
  // inside the dialog (selecting text) and ends outside must not close it.
  const pressedOnBackdrop = useRef(false)

  useEffect(() => {
    // Not closed here on cleanup: React StrictMode runs this effect twice, and a
    // close() in between would send a "close" event that shuts the dialog again.
    if (dialog.current && !dialog.current.open) dialog.current.showModal()
  }, [])

  return (
    <dialog
      ref={dialog}
      className="details-dialog"
      aria-labelledby={titleId}
      onClose={onClose}
      // The box fills the dialog, so a press on the dialog itself is a press on the backdrop.
      onPointerDown={(event) => {
        pressedOnBackdrop.current = event.target === event.currentTarget
      }}
      onClick={(event) => {
        if (pressedOnBackdrop.current && event.target === event.currentTarget) dialog.current?.close()
        pressedOnBackdrop.current = false
      }}
    >
      <div className="details-box">
        <header className="details-head">
          <div>
            <h2 id={titleId} className="details-title" translate="no">
              {visibleText(title)}
            </h2>
            <p className="details-sub">{subtitle}</p>
          </div>
          <button type="button" className="secondary" onClick={() => dialog.current?.close()}>
            Close
          </button>
        </header>
        <div className="details-body">{children}</div>
      </div>
    </dialog>
  )
}
