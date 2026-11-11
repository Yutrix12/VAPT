// Plain words for the report details.
import type { Kind } from '../api/types'
import { countText } from './text'

/** What the page shows for a field the uploaded format does not carry (U3). */
export const NOT_IN_FORMAT = 'not in this format'

/** "not in this format" when the report's format lacks `field`, else `value`. */
export function fieldOrNotInFormat(report: { not_in_format: string[] }, field: string, value: string): string {
  return report.not_in_format.includes(field) ? NOT_IN_FORMAT : value
}

// Fields a format can lack that the page shows nowhere else, in plain words.
const MISSING_FIELD_WORDS: Record<string, string> = {
  cvss_score: 'CVSS scores',
  published_date: 'published dates',
  full_titles: 'full vulnerability titles (Trivy shortens them)',
  misconfiguration_title: 'misconfiguration titles',
  resolution: 'fix texts for misconfigurations',
  link: 'license links',
  confidence: 'license confidence',
  check_id: 'misconfiguration IDs',
  rule_id: 'secret rule IDs',
}

/** What the report's format does not carry, as one list; null when nothing of it needs saying. */
export function missingFieldsText(report: { not_in_format: string[] }): string | null {
  const words = Object.entries(MISSING_FIELD_WORDS)
    .filter(([field]) => report.not_in_format.includes(field))
    .map(([, text]) => text)
  return words.length > 0 ? words.join(', ') : null
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

const KIND_LABELS: Record<Kind, string> = {
  vulnerability: 'Vulnerability',
  misconfiguration: 'Misconfiguration',
  secret: 'Secret',
  license: 'License',
}

/** "Vulnerability" for the kind of a finding. */
export function kindLabel(kind: Kind): string {
  return KIND_LABELS[kind]
}

/** "line 3" or "lines 7 to 9"; null when the report gives no line. */
export function lineText(start: number | null, end: number | null): string | null {
  if (start === null) return null
  return end === null || end === start ? `line ${start}` : `lines ${start} to ${end}`
}

/** "Showing 5 of 6 items": the rows of the findings table that match the filters. */
export function shownText(shown: number, total: number): string {
  return `Showing ${shown} of ${countText(total, 'item')}`
}

/**
 * The headline over the severity bar. A report with vulnerabilities only keeps
 * its short sentence; otherwise each kind that was found is listed.
 */
export function overviewText(byKind: Record<Kind, number>, packages: number): string {
  const total = byKind.vulnerability + byKind.misconfiguration + byKind.secret + byKind.license
  const others = byKind.misconfiguration + byKind.secret + byKind.license
  if (others === 0) return `${countText(total, 'finding')} in ${countText(packages, 'package')}`
  const parts = [
    byKind.vulnerability > 0 &&
      `${countText(byKind.vulnerability, 'vulnerability', 'vulnerabilities')} in ${countText(packages, 'package')}`,
    byKind.misconfiguration > 0 && countText(byKind.misconfiguration, 'misconfiguration'),
    byKind.secret > 0 && countText(byKind.secret, 'secret'),
    byKind.license > 0 && countText(byKind.license, 'license'),
  ].filter(Boolean)
  return `${countText(total, 'finding')}: ${parts.join(', ')}`
}

const MAX_NAME_LENGTH = 60

/**
 * What to call a misconfiguration: its ID and title; with neither (a text report
 * of the second layout), the start of its description, which is the check's own text.
 */
export function misconfigurationName(item: {
  check_id: string | null
  title: string | null
  description: string | null
}): string {
  const named = [item.check_id, item.title].filter(Boolean).join(': ')
  if (named !== '') return named
  const text = item.description?.trim() ?? ''
  if (text === '') return 'unknown check'
  return text.length <= MAX_NAME_LENGTH ? text : `${text.slice(0, MAX_NAME_LENGTH - 3).trimEnd()}...`
}

/** What to call a secret: its rule ID, or its title when the report has no rule ID, then the category. */
export function secretName(item: { rule_id: string | null; category: string | null; title: string | null }): string {
  const name = item.rule_id || item.title
  const category = item.category ? `(${item.category})` : ''
  return [name, category].filter(Boolean).join(' ') || 'unknown rule'
}

