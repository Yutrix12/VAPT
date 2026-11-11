import type { Severity } from '../api/types'
import { ALL_STATUSES } from '../reportLogic'
import { RATED_SEVERITIES, severityLabel } from '../shared/severity'
import { visibleText } from '../shared/text'

interface Props {
  severities: ReadonlySet<Severity>
  onSeveritiesChange: (next: Set<Severity>) => void
  counts: Record<Severity, number> // findings per severity in this report
  status: string
  statuses: string[] // the status values that appear in this report
  onStatusChange: (next: string) => void
}

/** Severity chips (real checkboxes; UNKNOWN apart) and a status list that filter the packages. */
export function Filters({ severities, onSeveritiesChange, counts, status, statuses, onStatusChange }: Props) {
  function toggle(severity: Severity) {
    const next = new Set(severities)
    if (next.has(severity)) next.delete(severity)
    else next.add(severity)
    onSeveritiesChange(next)
  }

  function chip(severity: Severity) {
    return (
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
    )
  }

  return (
    <fieldset className="panel">
      <legend className="panel-title">Filters</legend>
      <div className="chips">{RATED_SEVERITIES.map(chip)}</div>
      {/* UNKNOWN is not part of the ranking, so its chip stands apart. */}
      <div className="chips chips-apart" role="group" aria-labelledby="not-rated-label">
        <span id="not-rated-label" className="chips-label">
          Not rated
        </span>
        {chip('UNKNOWN')}
      </div>
      <label className="field">
        Status
        <select name="status" value={status} onChange={(event) => onStatusChange(event.target.value)}>
          <option value={ALL_STATUSES}>All statuses</option>
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
