import { describe, expect, it } from 'vitest'
import {
  ALL_STATUSES, checkFileBeforeUpload, countText, filterGroups, formatScanDate, isAnalyzeResult,
  KEEP_LINE_BREAKS, safeLink, visibleText,
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

  it('gives the worst severity of the shown findings', () => {
    const shown = filterGroups(groups, new Set<Severity>(['LOW']), ALL_STATUSES)
    expect(shown.map((g) => g.worst)).toEqual(['LOW', 'LOW'])
    expect(filterGroups(groups, all, ALL_STATUSES)[0].worst).toBe('CRITICAL')
  })
})

describe('visibleText', () => {
  it('makes invisible and direction-changing characters visible', () => {
    expect(visibleText('openssl\u202Elmth.exe')).toBe('openssl\\u202Elmth.exe')
    expect(visibleText('3.5.4\u200B')).toBe('3.5.4\\u200B')
    expect(visibleText('a\u001b[31mb')).toBe('a\\u001B[31mb')
  })

  it('also catches other invisible characters, above U+FFFF too', () => {
    const arabicMark = String.fromCodePoint(0x061c)
    const softHyphen = String.fromCodePoint(0x00ad)
    const tagA = String.fromCodePoint(0xe0041)
    expect(visibleText(`a${arabicMark}b${softHyphen}c${tagA}1`)).toBe('a\\u061Cb\\u00ADc\\u{E0041}1')
  })

  it('keeps line breaks and tabs only when asked (AI text)', () => {
    expect(visibleText('a\nb\tc', KEEP_LINE_BREAKS)).toBe('a\nb\tc')
    expect(visibleText('a\nb')).toBe('a\\u000Ab')
  })

  it('leaves ordinary text exactly as it is', () => {
    expect(visibleText('libssl3t64 3.5.7-1~deb13u3: Ünïcode, 日本')).toBe('libssl3t64 3.5.7-1~deb13u3: Ünïcode, 日本')
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
