import { ALL_STATUSES, severityLabel, visibleText } from '../reportLogic'
import { SEVERITIES, type Severity } from '../types'

interface Props {
  severities: ReadonlySet<Severity>
  onSeveritiesChange: (next: Set<Severity>) => void
  counts: Record<Severity, number> // findings per severity in this report
  status: string
  statuses: string[] // the status values that appear in this report
  onStatusChange: (next: string) => void
}

/** Severity chips (real checkboxes) and a status list that filter the package groups. */
export function Filters({ severities, onSeveritiesChange, counts, status, statuses, onStatusChange }: Props) {
  function toggle(severity: Severity) {
    const next = new Set(severities)
    if (next.has(severity)) next.delete(severity)
    else next.add(severity)
    onSeveritiesChange(next)
  }

  return (
    <fieldset className="panel">
      <legend className="panel-title">Filter</legend>
      <div className="chips">
        {SEVERITIES.map((severity) => (
          <label key={severity} className={`chip severity-${severity.toLowerCase()}`}>
            <input
              className="visually-hidden"
              type="checkbox"
              name="severity"
              checked={severities.has(severity)}
              onChange={() => toggle(severity)}
            />
            <span>{severityLabel(severity)}</span>
            <span className="chip-count">{counts[severity]}</span>
          </label>
        ))}
      </div>
      <label className="field">
        Status
        <select name="status" value={status} onChange={(event) => onStatusChange(event.target.value)}>
          <option value={ALL_STATUSES}>all</option>
          {statuses.map((value) => (
            // The value stays the real status, so the filter matches it.
            <option key={value} value={value}>
              {visibleText(value)}
            </option>
          ))}
        </select>
      </label>
    </fieldset>
  )
}
