import { describe, expect, it } from 'vitest'
import {
  checkFileBeforeUpload, countText, filterGroups, formatScanDate, isAnalyzeResult, safeLink,
  showHiddenCharacters,
} from './reportLogic'
import type { Finding, PackageGroup, Severity } from './types'

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
    fixed_versions: [], has_unfixed: true, findings,
  }
}

const MB = 1024 * 1024

describe('checkFileBeforeUpload', () => {
  it('accepts a .json file up to 50 MB', () => {
    expect(checkFileBeforeUpload('image.json', 3 * MB)).toBeNull()
    expect(checkFileBeforeUpload('REPORT.JSON', 50 * MB)).toBeNull()
  })

  it('refuses other file types with the agreed message', () => {
    expect(checkFileBeforeUpload('report.html', 10)).toBe(
      'Skipped report.html: only Trivy JSON reports are supported right now')
  })

  it('refuses files over 50 MB before uploading', () => {
    expect(checkFileBeforeUpload('big.json', 50 * MB + 1)).toBe(
      'Skipped big.json: the file is larger than 50 MB')
  })
})

describe('filterGroups', () => {
  const groups = [
    group('openssl', [finding('CRITICAL', 'fixed', 'A'), finding('LOW', 'affected', 'B')]),
    group('bash', [finding('LOW', 'affected', 'C')]),
  ]
  const all = new Set<Severity>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'])

  it('keeps everything without a filter', () => {
    const shown = filterGroups(groups, all, 'all')
    expect(shown.map((g) => g.findings.length)).toEqual([2, 1])
  })

  it('keeps only groups and findings that match', () => {
    const shown = filterGroups(groups, new Set<Severity>(['CRITICAL']), 'all')
    expect(shown.map((g) => g.group.pkg_name)).toEqual(['openssl'])
    expect(shown[0].findings.map((f) => f.vuln_id)).toEqual(['A'])
  })

  it('filters by status', () => {
    const shown = filterGroups(groups, all, 'affected')
    expect(shown.map((g) => g.findings.map((f) => f.vuln_id))).toEqual([['B'], ['C']])
  })

  it('gives the worst severity of the shown findings', () => {
    const shown = filterGroups(groups, new Set<Severity>(['LOW']), 'all')
    expect(shown.map((g) => g.worst)).toEqual(['LOW', 'LOW'])
    expect(filterGroups(groups, all, 'all')[0].worst).toBe('CRITICAL')
  })
})

describe('showHiddenCharacters', () => {
  it('makes invisible and direction-changing characters visible', () => {
    expect(showHiddenCharacters('openssl\u202Elmth.exe')).toBe('openssl\\u202Elmth.exe')
    expect(showHiddenCharacters('3.5.4\u200B')).toBe('3.5.4\\u200B')
    expect(showHiddenCharacters('a\u001b[31mb')).toBe('a\\u001B[31mb')
  })

  it('cleans every string in a nested answer and leaves the rest', () => {
    expect(showHiddenCharacters({ a: ['x\u202Ey', 3, null], b: { c: 'ok' } })).toEqual(
      { a: ['x\\u202Ey', 3, null], b: { c: 'ok' } })
  })
})

describe('isAnalyzeResult', () => {
  it('accepts the shape /api/analyze returns', () => {
    expect(isAnalyzeResult({
      report: {}, summary: { by_severity: {}, by_status: {} }, package_groups: [],
    })).toBe(true)
  })

  it('refuses other answers', () => {
    expect(isAnalyzeResult({})).toBe(false)
    expect(isAnalyzeResult([])).toBe(false)
    expect(isAnalyzeResult({ report: {}, summary: {}, package_groups: [] })).toBe(false)
  })
})

describe('safeLink', () => {
  it('allows http and https links only', () => {
    expect(safeLink('https://avd.aquasec.com/nvd/cve-2026-1')).toBe(
      'https://avd.aquasec.com/nvd/cve-2026-1')
    expect(safeLink('javascript:alert(1)')).toBeNull()
    expect(safeLink('data:text/html,<b>x</b>')).toBeNull()
    expect(safeLink('not a url')).toBeNull()
    expect(safeLink(null)).toBeNull()
  })
})

describe('countText', () => {
  it('uses the singular only for exactly one', () => {
    expect(countText(1, 'package')).toBe('1 package')
    expect(countText(0, 'package')).toBe('0 packages')
    expect(countText(54, 'package')).toBe('54 packages')
  })
})

describe('formatScanDate', () => {
  it('formats an ISO date and keeps anything else as it was', () => {
    expect(formatScanDate('2026-11-06T09:45:32.7294274+05:30', 'en-GB', 'UTC'))
      .toBe('6 Nov 2026, 04:15')
    expect(formatScanDate('not a date', 'en-GB', 'UTC')).toBe('not a date')
    expect(formatScanDate(null, 'en-GB', 'UTC')).toBe('unknown')
  })
})
