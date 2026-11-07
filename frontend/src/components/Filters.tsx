import { ALL_STATUSES } from '../reportLogic'
import { SEVERITIES, type Severity } from '../types'

interface Props {
  severities: ReadonlySet<Severity>
  onSeveritiesChange: (next: Set<Severity>) => void
  status: string
  statuses: string[] // the status values that appear in this report
  onStatusChange: (next: string) => void
}

/** Severity checkboxes and a status list that filter the package groups. */
export function Filters({ severities, onSeveritiesChange, status, statuses, onStatusChange }: Props) {
  function toggle(severity: Severity) {
    const next = new Set(severities)
    if (next.has(severity)) next.delete(severity)
    else next.add(severity)
    onSeveritiesChange(next)
  }

  return (
    <fieldset className="filters">
      <legend>Filter</legend>
      {SEVERITIES.map((severity) => (
        <label key={severity} className="check">
          <input
            type="checkbox"
            name="severity"
            checked={severities.has(severity)}
            onChange={() => toggle(severity)}
          />
          {severity}
        </label>
      ))}
      <label className="status-filter">
        Status{' '}
        <select name="status" value={status} onChange={(event) => onStatusChange(event.target.value)}>
          <option value={ALL_STATUSES}>all</option>
          {statuses.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
    </fieldset>
  )
}
