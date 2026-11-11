// The rows of the findings table: every finding kind in one list (no React here).
import type { AnalyzeResult, Kind, License, Misconfiguration, Secret, Severity } from '../../api/types'
import { compareSeverity } from '../../shared/severity'
import { kevCount } from '../../shared/threat'
import { filterGroups, matchesSearch, searchNeedle, type ShownGroup } from '../filters/filterGroups'
import { ALL_KINDS, type FilterState } from '../filters/filterState'
import { groupKey } from './groupKey'

export type Row =
  | { kind: 'vulnerability'; key: string; severity: Severity; shown: ShownGroup }
  | { kind: 'misconfiguration'; key: string; severity: Severity; item: Misconfiguration }
  | { kind: 'secret'; key: string; severity: Severity; item: Secret }
  | { kind: 'license'; key: string; severity: Severity; item: License }

/** The rows there are before any filter: one per package, plus one per other finding. */
export function totalRows(result: Kinds): number {
  return result.package_groups.length + result.misconfigurations.length + result.secrets.length + result.licenses.length
}

/** A row that is not a vulnerable package. */
export type OtherRow = Exclude<Row, { kind: 'vulnerability' }>

type Kinds = Pick<AnalyzeResult, 'package_groups' | 'misconfigurations' | 'secrets' | 'licenses'>

// Among equal severities the kinds keep the owner's order.
const KIND_ORDER: Record<Kind, number> = { vulnerability: 0, misconfiguration: 1, secret: 2, license: 3 }

/** The texts of a finding that the search looks in. */
function searchTexts(row: Exclude<Row, { kind: 'vulnerability' }>): (string | null)[] {
  switch (row.kind) {
    case 'misconfiguration': {
      const { item } = row
      return [item.check_id, item.title, item.description, item.target, item.resource]
    }
    case 'secret': {
      const { item } = row
      return [item.rule_id, item.category, item.title, item.target]
    }
    case 'license': {
      const { item } = row
      return [item.name, item.pkg_name, item.file_path, item.target, item.category]
    }
  }
}

/**
 * "Fix available" for a finding that is not a vulnerability: a misconfiguration
 * needs Trivy's own fix text, a secret always has its fixed steps, and a license
 * has no fix (only a note for the legal team).
 */
function hasFix(row: Exclude<Row, { kind: 'vulnerability' }>): boolean {
  switch (row.kind) {
    case 'misconfiguration':
      return Boolean(row.item.resolution)
    case 'secret':
      return true
    case 'license':
      return false
  }
}

/**
 * Every finding kind as one list, most severe first, after the filters. The
 * severity, kind, search and "fix available" filters apply to all kinds. The
 * status filter applies to vulnerabilities only: the other kinds have no status.
 * "Known exploited only" keeps vulnerabilities only too: the KEV list holds CVEs.
 * With the sort "Known exploited first", packages with a KEV CVE come first and
 * every other order stays as it was (Trivy's severity).
 */
export function buildRows(result: Kinds, filters: FilterState): Row[] {
  const { kind, severities, status, fixOnly, kevOnly } = filters
  const needle = searchNeedle(filters.search)
  const wanted = (rowKind: Kind) => kind === ALL_KINDS || kind === rowKind
  const rows: Row[] = []
  if (wanted('vulnerability')) {
    for (const shown of filterGroups(result.package_groups, severities, status, { search: filters.search, fixOnly, kevOnly })) {
      rows.push({ kind: 'vulnerability', key: groupKey(shown.group), severity: shown.worst, shown })
    }
  }
  const others = (rowKind: Exclude<Kind, 'vulnerability'>, items: (Misconfiguration | Secret | License)[]) => {
    if (!wanted(rowKind) || kevOnly) return
    items.forEach((item, index) => {
      const row = { kind: rowKind, key: `${rowKind}:${index}`, severity: item.severity, item } as Exclude<
        Row,
        { kind: 'vulnerability' }
      >
      if (severities.has(item.severity) && (!fixOnly || hasFix(row)) && matchesSearch(needle, ...searchTexts(row))) {
        rows.push(row)
      }
    })
  }
  others('misconfiguration', result.misconfigurations)
  others('secret', result.secrets)
  others('license', result.licenses)
  // The sort is stable, so a vulnerability tie keeps filterGroups' order (most shown findings first).
  rows.sort((a, b) => compareSeverity(a.severity, b.severity) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind])
  // A second, stable sort: the severity order above is kept inside each of the two groups.
  return filters.sort === 'kev' ? rows.sort((a, b) => Number(isExploitedRow(b)) - Number(isExploitedRow(a))) : rows
}

/** A package with at least one CVE on the KEV list (its whole group, not only the CVEs the filters keep). */
export function isExploitedRow(row: Row): boolean {
  return row.kind === 'vulnerability' && kevCount(row.shown.group.findings) > 0
}

/** Findings per severity over all kinds (the backend's counts are vulnerabilities only). */
export function severityCounts(
  result: Pick<AnalyzeResult, 'summary' | 'misconfigurations' | 'secrets' | 'licenses'>,
): Record<Severity, number> {
  const counts = { ...result.summary.by_severity }
  for (const item of [...result.misconfigurations, ...result.secrets, ...result.licenses]) {
    counts[item.severity] += 1
  }
  return counts
}
