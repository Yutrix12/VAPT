// Which package groups the severity and status filters leave visible.
import { type Finding, type PackageGroup, type Severity } from '../../api/types'
import { compareSeverity, worstSeverity } from '../../shared/severity'

/** The status filter value for "all statuses". A real status is never
 * empty (the parser writes "unknown"), so it cannot clash with one. */
export const ALL_STATUSES = ''

export interface ShownGroup {
  group: PackageGroup
  findings: Finding[] // only the findings that match the filters
  worst: Severity // the worst severity among those findings
}

/** Groups with at least one finding that matches the severity and status filters. */
export function filterGroups(
  groups: PackageGroup[],
  severities: ReadonlySet<Severity>,
  status: string, // ALL_STATUSES or one status value
): ShownGroup[] {
  const shown: ShownGroup[] = []
  for (const group of groups) {
    const findings = group.findings.filter(
      (f) => severities.has(f.severity) && (status === ALL_STATUSES || f.status === status),
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
