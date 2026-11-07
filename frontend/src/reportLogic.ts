// Plain functions behind the results page (no React here), so they are easy
// to test.
import { SEVERITIES, type AnalyzeResult, type Finding, type PackageGroup, type Severity } from './types'

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

/** "1 package" or "2 packages": the word gets an "s" unless count is 1. */
export function countText(count: number, word: string): string {
  return `${count} ${count === 1 ? word : `${word}s`}`
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
      const worstRank = Math.min(...findings.map((f) => SEVERITIES.indexOf(f.severity)))
      shown.push({ group, findings, worst: SEVERITIES[worstRank] })
    }
  }
  return shown
}

// Characters that are invisible or change the text direction: control
// characters, zero-width marks, bidi overrides and isolates, the BOM.
// eslint-disable-next-line no-control-regex -- matching them is the point
const HIDDEN_CHARACTERS = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060-\u2069\uFEFF]/g

/**
 * Report text is untrusted: an invisible or right-to-left character could
 * make a package or version look like something else. They are shown as
 * visible codes (e.g. \u202E), in every string of the value.
 */
export function showHiddenCharacters<T>(value: T): T {
  if (typeof value === 'string') {
    return value.replace(HIDDEN_CHARACTERS, (char) =>
      `\\u${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`) as T
  }
  if (Array.isArray(value)) return value.map(showHiddenCharacters) as T
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      // Keys too: status names, for example, are keys of by_status.
      Object.entries(value).map(([key, item]) => [showHiddenCharacters(key), showHiddenCharacters(item)]),
    ) as T
  }
  return value
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
