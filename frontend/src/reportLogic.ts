// Plain functions behind the results page (no React here), so they are easy
// to test.
import { type Finding, type PackageGroup, type Severity } from './api/types'
import { compareSeverity, worstSeverity } from './shared/severity'
import { countText } from './shared/text'

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024

/**
 * A reason to refuse the file before uploading it, or null if it is fine.
 * Only the size is checked here: the backend detects the format from the
 * content, never from the file name (U3).
 */
export function checkFileBeforeUpload(name: string, size: number): string | null {
  if (size > MAX_UPLOAD_BYTES) {
    return `Skipped ${name}: the file is larger than 50 MB`
  }
  return null
}

/** What the page shows for a field the uploaded format does not carry (U3). */
export const NOT_IN_FORMAT = 'not in this format'

/** "not in this format" when the report's format lacks `field`, else `value`. */
export function fieldOrNotInFormat(report: { not_in_format: string[] }, field: string, value: string): string {
  return report.not_in_format.includes(field) ? NOT_IN_FORMAT : value
}

/** The sentence for vulnerabilities that no upgrade closes (page and fix summary). */
export function openAfterUpgradeText(count: number): string {
  const one = count === 1
  return (
    `${countText(count, 'vulnerability', 'vulnerabilities')} in this package ${one ? 'has' : 'have'} ` +
    `no fixed version yet and ${one ? 'stays' : 'stay'} open after any upgrade.`
  )
}

// Trivy 0.76.2's artifact types (pkg/fanal/types/artifact.go) in plain words.
const ARTIFACT_TYPE_LABELS: Record<string, string> = {
  container_image: 'Container image',
  filesystem: 'Filesystem',
  repository: 'Repository',
  cyclonedx: 'CycloneDX SBOM',
  spdx: 'SPDX SBOM',
  aws_account: 'AWS account',
  vm: 'Virtual machine image',
}

/** "Container image" for container_image; any other value as Trivy wrote it. */
export function artifactTypeLabel(type: string | null): string {
  if (type === null) return 'unknown'
  return Object.hasOwn(ARTIFACT_TYPE_LABELS, type) ? ARTIFACT_TYPE_LABELS[type] : type
}

/** A unique key per group: JSON keeps null and "" apart, and needs no separator. */
export function groupKey(group: PackageGroup): string {
  return JSON.stringify([group.target, group.pkg_name, group.installed_version])
}

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
