// Which package groups the filters leave visible, and how text is matched.
import { type Finding, type PackageGroup, type Severity } from '../../api/types'
import { compareSeverity, worstSeverity } from '../../shared/severity'
import { isKnownExploited } from '../../shared/threat'

/** The status filter value for "all statuses". A real status is never
 * empty (the parser writes "unknown"), so it cannot clash with one. */
export const ALL_STATUSES = ''

export interface ShownGroup {
  group: PackageGroup
  findings: Finding[] // only the findings that match the filters
  worst: Severity // the worst severity among those findings
}

/** The text to search for: trimmed and lower-cased ("" means no search). */
export function searchNeedle(search: string | undefined): string {
  return (search ?? '').trim().toLowerCase()
}

/** True if there is no search, or any of the texts contains it (case does not matter). */
export function matchesSearch(needle: string, ...texts: (string | null | undefined)[]): boolean {
  return needle === '' || texts.some((text) => text?.toLowerCase().includes(needle))
}

interface GroupOptions {
  search?: string // matched against the package name, version and target; else each finding's ID and title
  fixOnly?: boolean // keep only the findings that have a fixed version
  kevOnly?: boolean // keep only the findings that are on the KEV list
}

/** Groups with at least one finding that matches the severity and status filters. */
export function filterGroups(
  groups: PackageGroup[],
  severities: ReadonlySet<Severity>,
  status: string, // ALL_STATUSES or one status value
  options: GroupOptions = {},
): ShownGroup[] {
  const needle = searchNeedle(options.search)
  const shown: ShownGroup[] = []
  for (const group of groups) {
    // A package that matches by its own name, version or target keeps all its findings.
    const groupMatches = matchesSearch(needle, group.pkg_name, group.installed_version, group.target)
    const findings = group.findings.filter(
      (f) =>
        severities.has(f.severity) &&
        (status === ALL_STATUSES || f.status === status) &&
        (!options.fixOnly || Boolean(f.fixed_version)) &&
        (!options.kevOnly || isKnownExploited(f)) &&
        (groupMatches || matchesSearch(needle, f.vuln_id, f.title)),
    )
    if (findings.length > 0) {
      shown.push({ group, findings, worst: worstSeverity(findings.map((f) => f.severity)) })
    }
  }
  // Filtering can lower a group's worst severity, so sort again: worst
  // first, then most shown findings. The sort is stable, so ties keep the
  // backend's order.
  return shown.sort((a, b) => compareSeverity(a.worst, b.worst) || b.findings.length - a.findings.length)
}
