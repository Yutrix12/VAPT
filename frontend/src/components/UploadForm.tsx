import { useState, type DragEvent, type FormEvent } from 'react'
import { analyzeReport } from '../api'
import { checkFileBeforeUpload, formatFileSize, visibleText } from '../reportLogic'
import type { AnalyzeResult } from '../types'

interface Props {
  onResult: (result: AnalyzeResult) => void // only called on success
}

/** Pick or drop one Trivy JSON report and send it to the backend. */
export function UploadForm({ onResult }: Props) {
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function choose(next: File | null) {
    setFile(next)
    setError(null)
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault() // the browser would otherwise open the file
    setDragging(false)
    const dropped = event.dataTransfer.files[0]
    // Dropped text or links carry no file; during an upload the choice stays.
    if (dropped !== undefined && !busy) choose(dropped)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (file === null) {
      setError('Choose a report first.')
      return
    }
    const problem = checkFileBeforeUpload(file.name, file.size)
    if (problem !== null) {
      setError(problem)
      return
    }
    // The current results stay on screen until a new report succeeds.
    setBusy(true)
    setError(null)
    const result = await analyzeReport(file)
    setBusy(false)
    if (result.ok) onResult(result.data)
    else setError(result.message)
  }

  return (
    <form className="panel" onSubmit={handleSubmit} aria-labelledby="upload-heading">
      <h2 id="upload-heading" className="panel-title">
        Upload a report
      </h2>
      <label
        className={dragging ? 'dropzone is-dragging' : 'dropzone'}
        onDragOver={(event) => {
          event.preventDefault() // needed to allow a drop here
          setDragging(true)
        }}
        onDragLeave={(event) => {
          // Moving onto the text inside the zone also fires dragleave: ignore that.
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false)
        }}
        onDrop={handleDrop}
      >
        <input
          className="visually-hidden"
          name="report"
          type="file"
          accept=".json,application/json"
          // Clear the old choice, so picking the same file again (e.g. after
          // fixing it) still counts as a change.
          // If the dialog is then cancelled, no file stays chosen unseen.
          onClick={(event) => {
            event.currentTarget.value = ''
            setFile(null)
          }}
          onChange={(event) => choose(event.target.files?.[0] ?? null)}
        />
        <span className="dropzone-title" translate={file ? 'no' : undefined}>
          {file ? visibleText(file.name) : 'Drop a Trivy JSON report'}
        </span>
        <span className="dropzone-hint">{file ? formatFileSize(file.size) : 'or click to choose a file'}</span>
      </label>
      <button type="submit" className="primary wide" disabled={busy}>
        {busy ? 'Analyzing…' : 'Analyze report'}
      </button>
      <p className="form-error" role="alert">
        {visibleText(error ?? '')}
      </p>
    </form>
  )
}
