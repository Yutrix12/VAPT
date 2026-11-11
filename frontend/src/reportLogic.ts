// Plain functions behind the results page (no React here), so they are easy
// to test.
import { SEVERITIES, type AnalyzeResult, type Finding, type PackageGroup, type RatedSeverity, type Severity } from './types'

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024

/** A reason to refuse the file before uploading it, or null if it is fine. */
export function checkFileBeforeUpload(name: string, size: number): string | null {
  if (!name.toLowerCase().endsWith('.json')) {
    return `Skipped ${name}: only Trivy JSON reports are supported right now`
  }
  if (size > MAX_UPLOAD_BYTES) {
    return `Skipped ${name}: the file is larger than 50 MB`
  }
  return null
}

// Severity levels: a higher number is more severe. UNKNOWN has no level:
// Trivy could not rate it, so it stays outside the ranking (same as the backend).
const SEVERITY_LEVELS: Record<RatedSeverity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

/** The rated severities, most severe first. */
export const RATED_SEVERITIES = SEVERITIES.filter((s): s is RatedSeverity => s !== 'UNKNOWN')

/** 4 for CRITICAL down to 1 for LOW; null for UNKNOWN (not rated). */
export function severityLevel(severity: Severity): number | null {
  return severity === 'UNKNOWN' ? null : SEVERITY_LEVELS[severity]
}

/** Below 0 when a is more severe than b; UNKNOWN comes after every rated severity. */
export function compareSeverity(a: Severity, b: Severity): number {
  const levelA = severityLevel(a)
  const levelB = severityLevel(b)
  if (levelA === null || levelB === null) return (levelA === null ? 1 : 0) - (levelB === null ? 1 : 0)
  return levelB - levelA
}

/** The most severe rated severity; UNKNOWN only when nothing is rated. */
export function worstSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>((worst, s) => (compareSeverity(s, worst) < 0 ? s : worst), 'UNKNOWN')
}

/** "Critical" for CRITICAL: calmer to read than all capitals. */
export function severityLabel(severity: Severity): string {
  return severity.charAt(0) + severity.slice(1).toLowerCase()
}

/** A file size for people: "512 bytes", "2 KB" or "1.5 MB" (no line break before the unit). */
export function formatFileSize(bytes: number): string {
  const nbsp = '\u00a0'
  if (bytes < 1024) return countText(bytes, 'byte')
  const kilobytes = Math.round(bytes / 1024)
  if (kilobytes < 1024) return `${kilobytes}${nbsp}KB` // rounded first, so never "1024 KB"
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(/\.0$/, '')}${nbsp}MB`
}

/** "1 package" or "2 packages"; give the plural when it is not word + "s" ("vulnerabilities"). */
export function countText(count: number, word: string, plural = `${word}s`): string {
  return `${count} ${count === 1 ? word : plural}`
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

// Control, format (invisible, direction-changing), line/paragraph separator
// and unassigned characters; Python's isprintable(), used on the backend,
// refuses these too. The u flag also matches characters above U+FFFF.
const HIDDEN_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cn}]/gu

/** Line breaks and tabs, which the backend keeps in the AI's text. */
export const KEEP_LINE_BREAKS = '\n\t'

/**
 * Report and AI text is untrusted: an invisible or right-to-left character
 * could make a package or version look like something else. Wrap such text
 * in this where it is shown: those characters appear as visible codes (a
 * backslash, "u" and the hex number), except those in `keep`. The data
 * itself stays exactly as Trivy wrote it, so filters, keys and /api/fix
 * use the real values.
 */
export function visibleText(text: string, keep = ''): string {
  return text.replace(HIDDEN_CHARACTERS, (char) => {
    if (keep.includes(char)) return char
    const code = char.codePointAt(0) ?? 0
    const hex = code.toString(16).toUpperCase()
    // Braces above U+FFFF, so "\u{E0041}" is not read as \uE004 plus "1".
    return code > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, '0')}`
  })
}

/** True for a plain JSON object (not null, not an array). */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** A light check that an answer has the shape of /api/analyze's response. */
export function isAnalyzeResult(body: unknown): body is AnalyzeResult {
  return (
    isObject(body) &&
    isObject(body.report) &&
    isObject(body.summary) &&
    isObject(body.summary.by_severity) &&
    isObject(body.summary.by_status) &&
    Array.isArray(body.package_groups)
  )
}

/** The link if it is a plain http(s) address, else null (no javascript: etc.). */
export function safeLink(url: string | null): string | null {
  if (url === null) return null
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null
  } catch {
    return null // not a valid absolute URL
  }
}

/**
 * The scan time in the reader's locale. Trivy writes up to 9 fractional
 * digits. The JavaScript date standard defines 3 (Chrome accepts more,
 * other browsers may not), so the rest is cut first.
 */
export function formatScanDate(value: string | null, locale?: string, timeZone?: string): string {
  if (value === null) return 'unknown'
  const date = new Date(value.replace(/(\.\d{3})\d+/, '$1'))
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(date)
}
