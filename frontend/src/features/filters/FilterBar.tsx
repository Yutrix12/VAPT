import type { Kind, Severity } from '../../api/types'
import { RATED_SEVERITIES, severityLabel } from '../../shared/severity'
import { visibleText } from '../../shared/text'
import { ALL_STATUSES } from './filterGroups'
import {
  ALL_KINDS,
  defaultFilters,
  isFiltering,
  statusApplies,
  withKind,
  type FilterState,
  type SortOrder,
} from './filterState'

interface Props {
  filters: FilterState
  onChange: (next: FilterState) => void
  counts: Record<Severity, number> // findings per severity in this report, all kinds
  statuses: string[] // the status values that appear in this report
  kevLoaded: boolean // the KEV list is loaded, so "Known exploited" can be filtered and sorted
}

const KIND_CHOICES: { value: Kind; label: string }[] = [
  { value: 'vulnerability', label: 'Vulnerabilities' },
  { value: 'misconfiguration', label: 'Misconfigurations' },
  { value: 'secret', label: 'Secrets' },
  { value: 'license', label: 'Licenses' },
]

/**
 * The filters above the findings table: search, kind, status, "fix available"
 * and the severity chips (real checkboxes; UNKNOWN apart), with "Clear all".
 */
export function FilterBar({ filters, onChange, counts, statuses, kevLoaded }: Props) {
  // Only vulnerabilities have a status, so the list waits for a kind that has one.
  const hasStatus = statusApplies(filters.kind)

  function toggle(severity: Severity) {
    const next = new Set(filters.severities)
    if (next.has(severity)) next.delete(severity)
    else next.add(severity)
    onChange({ ...filters, severities: next })
  }

  function chip(severity: Severity) {
    return (
      <label key={severity} className={`chip severity-${severity.toLowerCase()}`}>
        <input
          className="visually-hidden"
          type="checkbox"
          name="severity"
          checked={filters.severities.has(severity)}
          onChange={() => toggle(severity)}
        />
        <span>{severityLabel(severity)}</span>
        <span className="chip-count">{counts[severity]}</span>
      </label>
    )
  }

  return (
    <form
      className="filter-bar"
      role="search"
      aria-label="Filter the findings"
      onSubmit={(event) => event.preventDefault()}
    >
      <div className="filter-row">
        <label className="field filter-search">
          Search
          <input
            type="search"
            name="search"
            value={filters.search}
            placeholder="Name, file, CVE ID, title"
            autoComplete="off"
            onChange={(event) => onChange({ ...filters, search: event.target.value })}
          />
        </label>
        <label className="field">
          Kind
          <select
            name="kind"
            value={filters.kind}
            onChange={(event) => onChange(withKind(filters, event.target.value as FilterState['kind']))}
          >
            <option value={ALL_KINDS}>All kinds</option>
            {KIND_CHOICES.map((choice) => (
              <option key={choice.value} value={choice.value}>
                {choice.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Status
          <select
            name="status"
            value={filters.status}
            disabled={!hasStatus}
            aria-describedby={hasStatus ? undefined : 'status-hint'}
            onChange={(event) => onChange({ ...filters, status: event.target.value })}
          >
            <option value={ALL_STATUSES}>All statuses</option>
            {statuses.map((value) => (
              // The value stays the real status, so the filter matches it.
              <option key={value} value={value}>
                {visibleText(value)}
              </option>
            ))}
          </select>
        </label>
        <label className="check">
          <input
            type="checkbox"
            name="fix-available"
            checked={filters.fixOnly}
            onChange={(event) => onChange({ ...filters, fixOnly: event.target.checked })}
          />
          Fix available
        </label>
        <label className="check">
          <input
            type="checkbox"
            name="known-exploited-only"
            checked={filters.kevOnly}
            // Without the KEV list the filter would hide everything and mean nothing; a filter that is already on can be turned off.
            disabled={!kevLoaded && !filters.kevOnly}
            aria-describedby={kevLoaded ? undefined : 'kev-hint'}
            onChange={(event) => onChange({ ...filters, kevOnly: event.target.checked })}
          />
          Known exploited only
        </label>
        <label className="field">
          Sort by
          <select
            name="sort"
            value={filters.sort}
            onChange={(event) => onChange({ ...filters, sort: event.target.value as SortOrder })}
          >
            <option value="severity">Trivy severity (default)</option>
            <option value="kev" disabled={!kevLoaded && filters.sort !== 'kev'}>
              Known exploited first
            </option>
          </select>
        </label>
        <button
          type="button"
          className="secondary"
          disabled={!isFiltering(filters)}
          onClick={() => onChange(defaultFilters())}
        >
          Clear all
        </button>
      </div>
      {!kevLoaded && (
        <p id="kev-hint" className="muted filter-hint">
          Known exploited (CISA KEV) data is not loaded, so it cannot be filtered or sorted.
        </p>
      )}
      {!hasStatus && (
        <p id="status-hint" className="muted filter-hint">
          Status applies to vulnerabilities only.
        </p>
      )}
      <div className="filter-row">
        <div className="chips" role="group" aria-label="Severity">
          {RATED_SEVERITIES.map(chip)}
        </div>
        {/* UNKNOWN is not part of the ranking, so its chip stands apart. */}
        <div className="chips" role="group" aria-labelledby="not-rated-label">
          <span id="not-rated-label" className="chips-label">
            Not rated
          </span>
          {chip('UNKNOWN')}
        </div>
      </div>
    </form>
  )
}
