// The rows of the findings table: every finding kind in one list (no React here).
import type { AnalyzeResult, License, Misconfiguration, Secret, Severity } from '../../api/types'
import { compareSeverity } from '../../shared/severity'
import { filterGroups, type ShownGroup } from '../filters/filterGroups'
import { groupKey } from './groupKey'

export type Row =
  | { kind: 'vulnerability'; key: string; severity: Severity; shown: ShownGroup }
  | { kind: 'misconfiguration'; key: string; severity: Severity; item: Misconfiguration }
  | { kind: 'secret'; key: string; severity: Severity; item: Secret }
  | { kind: 'license'; key: string; severity: Severity; item: License }

type Kinds = Pick<AnalyzeResult, 'package_groups' | 'misconfigurations' | 'secrets' | 'licenses'>

// Among equal severities the kinds keep the owner's order.
const KIND_ORDER: Record<Row['kind'], number> = { vulnerability: 0, misconfiguration: 1, secret: 2, license: 3 }

/**
 * Every finding kind as one list, most severe first. The severity filter
 * applies to all kinds. The status filter applies to vulnerabilities only:
 * the other kinds have no status.
 */
export function buildRows(result: Kinds, severities: ReadonlySet<Severity>, status: string): Row[] {
  const rows: Row[] = filterGroups(result.package_groups, severities, status).map((shown) => ({
    kind: 'vulnerability',
    key: groupKey(shown.group),
    severity: shown.worst,
    shown,
  }))
  const others = (kind: Exclude<Row['kind'], 'vulnerability'>, items: (Misconfiguration | Secret | License)[]) =>
    items.forEach((item, index) => {
      if (severities.has(item.severity)) {
        rows.push({ kind, key: `${kind}:${index}`, severity: item.severity, item } as Row)
      }
    })
  others('misconfiguration', result.misconfigurations)
  others('secret', result.secrets)
  others('license', result.licenses)
  // The sort is stable, so a vulnerability tie keeps filterGroups' order (most shown findings first).
  return rows.sort((a, b) => compareSeverity(a.severity, b.severity) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind])
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
