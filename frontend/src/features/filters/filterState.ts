// What the filter bar holds (no React here).
import { SEVERITIES, type Kind, type Severity } from '../../api/types'
import { ALL_STATUSES } from './filterGroups'

/** The kind filter value for "all kinds". */
export const ALL_KINDS = 'all'

/** The order of the rows: Trivy's severity (the default), or known exploited (CISA KEV) packages first. */
export type SortOrder = 'severity' | 'kev'

export interface FilterState {
  search: string // text to find in names, places, CVE IDs and titles; blank filters nothing
  kind: Kind | typeof ALL_KINDS
  severities: ReadonlySet<Severity> // the severities that stay visible
  status: string // ALL_STATUSES or one status value (applies to vulnerabilities only)
  fixOnly: boolean // "fix available"
  kevOnly: boolean // "Known exploited only": packages with a CVE on the KEV list (other kinds have none)
  sort: SortOrder
}

/** Nothing filtered. A new state each time, so one reset never shares a Set with another. */
export function defaultFilters(): FilterState {
  return { search: '', kind: ALL_KINDS, severities: new Set(SEVERITIES), status: ALL_STATUSES, fixOnly: false, kevOnly: false, sort: 'severity' }
}

/** True if any filter is on, or the order is not the default (so "Clear all" has something to clear). */
export function isFiltering(filters: FilterState): boolean {
  return (
    filters.search.trim() !== '' ||
    filters.kind !== ALL_KINDS ||
    filters.status !== ALL_STATUSES ||
    filters.fixOnly ||
    filters.kevOnly ||
    filters.sort !== 'severity' ||
    SEVERITIES.some((severity) => !filters.severities.has(severity))
  )
}

/** Only vulnerabilities have a status, so a status filter makes sense for them (and for all kinds). */
export function statusApplies(kind: FilterState['kind']): boolean {
  return kind === ALL_KINDS || kind === 'vulnerability'
}

/**
 * The filters with another kind. A status is cleared when the new kind has
 * none, so no hidden filter stays on (it would come back when the kind changes
 * again, and the fix summary would name a filter that was not applied).
 */
export function withKind(filters: FilterState, kind: FilterState['kind']): FilterState {
  return { ...filters, kind, status: statusApplies(kind) ? filters.status : ALL_STATUSES }
}
