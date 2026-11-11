import { describe, expect, it } from 'vitest'
import type { AnalyzeResult, Finding, License, Misconfiguration, PackageGroup, Secret, Severity } from '../../api/types'
import { defaultFilters, type FilterState } from '../filters/filterState'
import { buildRows, severityCounts } from './rows'

function finding(severity: Severity, status: string, id: string): Finding {
  return {
    fingerprint: id, target: 't', vuln_class: 'os-pkgs', vuln_type: 'debian', vuln_id: id, pkg_name: 'p',
    installed_version: '1', fixed_version: null, status, severity, title: 'a bug', cvss_score: null,
    primary_url: null, published_date: null,
  }
}

function group(name: string, findings: Finding[]): PackageGroup {
  return {
    target: 't', pkg_name: name, installed_version: '1', finding_count: findings.length,
    worst_severity: findings[0].severity, fixed_versions: [], has_unfixed: true, findings,
  }
}

const misconfiguration = (severity: Severity, id: string): Misconfiguration => ({
  fingerprint: id, target: 'Dockerfile', misconf_type: 'dockerfile', check_type: null, check_id: id, title: null,
  description: 'd', resolution: null, severity, status: 'FAIL', primary_url: null, references: [], resource: null,
  start_line: null, end_line: null,
})

const secret = (severity: Severity, rule: string): Secret => ({
  fingerprint: rule, target: 'deploy.sh', rule_id: rule, category: 'AWS', severity, title: 't', start_line: 3,
  end_line: 3,
})

const license = (severity: Severity, name: string): License => ({
  fingerprint: name, target: 'Java', license_class: 'license', pkg_name: 'pkg', file_path: null, name,
  category: 'notice', severity, confidence: null, link: null,
})

const result: Pick<AnalyzeResult, 'package_groups' | 'misconfigurations' | 'secrets' | 'licenses' | 'summary'> = {
  package_groups: [
    group('openssl', [finding('CRITICAL', 'fixed', 'A'), finding('LOW', 'affected', 'B')]),
    group('bash', [finding('LOW', 'affected', 'C')]),
  ],
  misconfigurations: [misconfiguration('HIGH', 'DS-0002'), misconfiguration('LOW', 'DS-0026')],
  secrets: [secret('CRITICAL', 'aws-key')],
  licenses: [license('MEDIUM', 'EPL-1.0')],
  summary: {
    total: 3, by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 2, UNKNOWN: 0 }, by_status: { fixed: 1, affected: 2 },
    unique_vuln_ids: 3, unique_packages: 2, without_fixed_version: 2, distinct_fingerprints: 3,
    by_kind: { vulnerability: 3, misconfiguration: 2, secret: 1, license: 1 }, misconfig_passed: 0,
    misconfig_exceptions: 0,
  },
}

/** The default filters (nothing filtered) with some changed. */
function filters(changes: Partial<FilterState> = {}): FilterState {
  return { ...defaultFilters(), ...changes }
}

function summary(rows: ReturnType<typeof buildRows>): string[] {
  return rows.map((row) => `${row.kind}:${row.severity}`)
}

describe('buildRows', () => {
  it('puts every kind in one list, most severe first, ties in the order vulnerabilities, misconfigurations, secrets, licenses', () => {
    expect(summary(buildRows(result, filters()))).toEqual([
      'vulnerability:CRITICAL', // openssl
      'secret:CRITICAL',
      'misconfiguration:HIGH',
      'license:MEDIUM',
      'vulnerability:LOW', // bash
      'misconfiguration:LOW',
    ])
  })

  it('keeps a vulnerability row to the findings that match the filters', () => {
    const rows = buildRows(result, filters({ severities: new Set<Severity>(['LOW']) }))
    expect(rows[0].kind === 'vulnerability' && rows[0].shown.findings.map((f) => f.vuln_id)).toEqual(['B'])
  })

  it('hides the rows of a severity that is switched off, for every kind', () => {
    expect(summary(buildRows(result, filters({ severities: new Set<Severity>(['CRITICAL']) })))).toEqual([
      'vulnerability:CRITICAL',
      'secret:CRITICAL',
    ])
    expect(buildRows(result, filters({ severities: new Set() }))).toEqual([])
  })

  it('applies the status filter to vulnerabilities only: the other kinds have no status', () => {
    expect(summary(buildRows(result, filters({ status: 'fixed' })))).toEqual([
      'vulnerability:CRITICAL',
      'secret:CRITICAL',
      'misconfiguration:HIGH',
      'license:MEDIUM',
      'misconfiguration:LOW',
    ])
  })

  it('gives every row its own key', () => {
    const keys = buildRows(result, filters()).map((row) => row.key)
    expect(new Set(keys).size).toBe(keys.length)
  })
})

describe('buildRows: kind, search and fix available', () => {
  const withFix = {
    ...result,
    misconfigurations: [
      { ...misconfiguration('HIGH', 'DS-0002'), resolution: 'Add a USER line.' },
      misconfiguration('LOW', 'DS-0026'),
    ],
    package_groups: [
      group('openssl', [{ ...finding('CRITICAL', 'fixed', 'A'), fixed_version: '3.0.1' }, finding('LOW', 'affected', 'B')]),
      group('bash', [finding('LOW', 'affected', 'C')]),
    ],
  }

  it('shows one kind only', () => {
    expect(summary(buildRows(withFix, filters({ kind: 'secret' })))).toEqual(['secret:CRITICAL'])
    expect(summary(buildRows(withFix, filters({ kind: 'vulnerability' })))).toEqual([
      'vulnerability:CRITICAL', 'vulnerability:LOW'])
    expect(summary(buildRows(withFix, filters({ kind: 'license' })))).toEqual(['license:MEDIUM'])
  })

  it('searches the item name and place of every kind', () => {
    expect(summary(buildRows(withFix, filters({ search: 'ds-0026' })))).toEqual(['misconfiguration:LOW'])
    expect(summary(buildRows(withFix, filters({ search: 'deploy.sh' })))).toEqual(['secret:CRITICAL'])
    expect(summary(buildRows(withFix, filters({ search: 'epl-1' })))).toEqual(['license:MEDIUM'])
    expect(summary(buildRows(withFix, filters({ search: 'dockerfile' })))).toEqual([
      'misconfiguration:HIGH', 'misconfiguration:LOW'])
  })

  it('fix available: a fixed version, Trivy fix text or any secret; never a license', () => {
    expect(summary(buildRows(withFix, filters({ fixOnly: true })))).toEqual([
      'vulnerability:CRITICAL', // openssl, with only its fixed finding
      'secret:CRITICAL',
      'misconfiguration:HIGH', // has a resolution
    ])
    const first = buildRows(withFix, filters({ fixOnly: true }))[0]
    expect(first.kind === 'vulnerability' && first.shown.findings.map((f) => f.vuln_id)).toEqual(['A'])
  })

  it('combines the filters', () => {
    expect(summary(buildRows(withFix, filters({ fixOnly: true, kind: 'misconfiguration', search: 'ds' })))).toEqual([
      'misconfiguration:HIGH'])
    expect(buildRows(withFix, filters({ kind: 'secret', search: 'nothing' }))).toEqual([])
  })
})

describe('severityCounts', () => {
  it('adds the other kinds to the vulnerability counts', () => {
    expect(severityCounts(result)).toEqual({ CRITICAL: 2, HIGH: 1, MEDIUM: 1, LOW: 3, UNKNOWN: 0 })
  })

  it('is the vulnerability counts when the report has no other kind', () => {
    const only = { ...result, misconfigurations: [], secrets: [], licenses: [] }
    expect(severityCounts(only)).toEqual(result.summary.by_severity)
  })
})
