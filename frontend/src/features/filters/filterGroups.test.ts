import { describe, expect, it } from 'vitest'
import type { Finding, PackageGroup, Severity } from '../../api/types'
import { ALL_STATUSES, filterGroups } from './filterGroups'

function finding(severity: Severity, status: string, id: string): Finding {
  return {
    fingerprint: id, target: 't', vuln_class: 'os-pkgs', vuln_type: 'debian',
    vuln_id: id, pkg_name: 'openssl', installed_version: '1.0', fixed_version: null,
    status, severity, title: 'a bug', cvss_score: null, primary_url: null,
    published_date: null,
  }
}

function group(name: string, findings: Finding[]): PackageGroup {
  return {
    target: 't', pkg_name: name, installed_version: '1.0',
    finding_count: findings.length, worst_severity: findings[0].severity,
    fixed_versions: [], has_unfixed: true, findings, fix_commands: [], fix_commands_note: null,
  }
}

describe('filterGroups', () => {
  const groups = [
    group('openssl', [finding('CRITICAL', 'fixed', 'A'), finding('LOW', 'affected', 'B')]),
    group('bash', [finding('LOW', 'affected', 'C')]),
  ]
  const all = new Set<Severity>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])

  it('keeps everything without a filter', () => {
    const shown = filterGroups(groups, all, ALL_STATUSES)
    expect(shown.map((g) => g.findings.length)).toEqual([2, 1])
  })

  it('keeps only groups and findings that match', () => {
    const shown = filterGroups(groups, new Set<Severity>(['CRITICAL']), ALL_STATUSES)
    expect(shown.map((g) => g.group.pkg_name)).toEqual(['openssl'])
    expect(shown[0].findings.map((f) => f.vuln_id)).toEqual(['A'])
  })

  it('never mixes up "all statuses" with a status called all', () => {
    const odd = [group('x', [finding('LOW', 'all', 'Z')]), group('y', [finding('LOW', 'fixed', 'Y')])]
    expect(filterGroups(odd, all, 'all').map((g) => g.group.pkg_name)).toEqual(['x'])
  })

  it('filters by status', () => {
    const shown = filterGroups(groups, all, 'affected')
    expect(shown.map((g) => g.findings.map((f) => f.vuln_id))).toEqual([['B'], ['C']])
  })

  it('keeps the shown groups worst first after filtering, with UNKNOWN last', () => {
    const mixed = [
      group('a', [finding('CRITICAL', 'fixed', 'A1'), finding('LOW', 'fixed', 'A2'), finding('LOW', 'fixed', 'A3')]),
      group('b', [finding('HIGH', 'fixed', 'B1')]),
      group('c', [finding('UNKNOWN', 'fixed', 'C1'), finding('UNKNOWN', 'fixed', 'C2')]),
      group('d', [finding('LOW', 'fixed', 'D1')]),
    ]
    const noCritical = new Set<Severity>(['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])
    // Without its CRITICAL finding, "a" is a LOW group: after "b", and
    // before "d" because it shows more findings; UNKNOWN-only "c" comes last.
    expect(filterGroups(mixed, noCritical, ALL_STATUSES).map((g) => `${g.group.pkg_name}:${g.worst}`))
      .toEqual(['b:HIGH', 'a:LOW', 'd:LOW', 'c:UNKNOWN'])
  })

  it('gives the worst severity of the shown findings', () => {
    const shown = filterGroups(groups, new Set<Severity>(['LOW']), ALL_STATUSES)
    expect(shown.map((g) => g.worst)).toEqual(['LOW', 'LOW'])
    expect(filterGroups(groups, all, ALL_STATUSES)[0].worst).toBe('CRITICAL')
  })
})

describe('filterGroups search and fix available', () => {
  const withFix = (id: string, title: string, fixed: string | null): Finding =>
    ({ ...finding('HIGH', 'fixed', id), title, fixed_version: fixed })
  const groups = [
    { ...group('openssl', [withFix('CVE-1', 'heap overflow', '3.0.1'), withFix('CVE-2', 'timing leak', null)]), installed_version: '3.0.0' },
    group('Bash', [withFix('CVE-3', 'privilege escalation', null)]),
  ]
  const all = new Set<Severity>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])
  const ids = (shown: ReturnType<typeof filterGroups>) =>
    shown.map((g) => `${g.group.pkg_name}:${g.findings.map((f) => f.vuln_id).join('+')}`)

  it('ignores an empty or blank search', () => {
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: '   ' }))).toEqual(['openssl:CVE-1+CVE-2', 'Bash:CVE-3'])
  })

  it('keeps every finding of a package whose name, version or target matches, ignoring case', () => {
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: 'BASH' }))).toEqual(['Bash:CVE-3'])
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: '3.0.0' }))).toEqual(['openssl:CVE-1+CVE-2'])
  })

  it('keeps only the findings whose ID or title matches when the package itself does not', () => {
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: 'cve-2' }))).toEqual(['openssl:CVE-2'])
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: 'escalation' }))).toEqual(['Bash:CVE-3'])
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: 'no such thing' }))).toEqual([])
  })

  it('fix available keeps the findings that have a fixed version, and drops packages without one', () => {
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { fixOnly: true }))).toEqual(['openssl:CVE-1'])
  })

  it('combines search, fix available, severity and status', () => {
    expect(ids(filterGroups(groups, all, ALL_STATUSES, { search: 'openssl', fixOnly: true }))).toEqual(['openssl:CVE-1'])
    expect(ids(filterGroups(groups, new Set<Severity>(['LOW']), ALL_STATUSES, { search: 'openssl' }))).toEqual([])
  })
})
