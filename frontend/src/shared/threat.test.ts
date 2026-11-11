import { describe, expect, it } from 'vitest'
import type { Finding, FindingThreat, ThreatData, ThreatSource } from '../api/types'
import {
  epssCellText,
  highestEpss,
  isKnownExploited,
  kevCellText,
  kevCount,
  kevLoaded,
  packageEpssText,
  packageKevText,
  threatStatusText,
} from './threat'

const threat = (kev: FindingThreat['kev'], epss: number | null, epssState?: FindingThreat['epss_state']): FindingThreat => ({
  kev,
  epss,
  epss_state: epssState ?? (epss === null ? 'not_listed' : 'listed'),
})

function finding(id: string, found?: FindingThreat): Finding {
  return {
    fingerprint: id, target: 't', vuln_class: 'lang-pkgs', vuln_type: 'pip', vuln_id: id, pkg_name: 'demo',
    installed_version: '1', fixed_version: '2', status: 'fixed', severity: 'HIGH', title: null, cvss_score: null,
    primary_url: null, published_date: null, ...(found ? { threat: found } : {}),
  }
}

describe('known exploited (CISA KEV) of a package', () => {
  const two = [finding('CVE-1', threat('listed', 0.97)), finding('CVE-2', threat('not_listed', 0.002))]

  it('is true for a CVE the list holds, false for one it does not, false for no data', () => {
    expect(isKnownExploited(two[0])).toBe(true)
    expect(isKnownExploited(two[1])).toBe(false)
    expect(isKnownExploited(finding('CVE-3'))).toBe(false)
    expect(isKnownExploited(finding('CVE-4', threat('no_data', null, 'no_data')))).toBe(false)
  })

  it('counts only the CVEs that are listed (a package with two CVEs and one in KEV)', () => {
    expect(kevCount(two)).toBe(1)
    expect(kevCount([two[1], finding('CVE-3')])).toBe(0)
  })
})

describe('highest exploit probability (EPSS)', () => {
  it('is the highest score and the CVE it belongs to', () => {
    const findings = [
      finding('CVE-1', threat('not_listed', 0.002)),
      finding('CVE-2', threat('listed', 0.97)),
      finding('CVE-3', threat('not_listed', 0.5)),
    ]
    expect(highestEpss(findings)).toEqual({ value: 0.97, id: 'CVE-2' })
  })

  it('is null when no CVE has a score: nothing is guessed, and 0 is not "no data"', () => {
    expect(highestEpss([finding('CVE-1'), finding('GHSA-1', threat('not_cve', null, 'not_cve'))])).toBeNull()
    expect(highestEpss([finding('CVE-1', threat('not_listed', null))])).toBeNull()
    expect(highestEpss([finding('CVE-1', threat('not_listed', 0))])).toEqual({ value: 0, id: 'CVE-1' })
  })
})

describe('the words for one CVE', () => {
  it('says yes, not listed, no data or not a CVE ID for KEV, and never mixes them up', () => {
    expect(kevCellText(threat('listed', 0.1))).toBe('Yes')
    expect(kevCellText(threat('not_listed', 0.1))).toBe('Not listed')
    expect(kevCellText(threat('no_data', null, 'no_data'))).toBe('No data')
    expect(kevCellText(threat('not_cve', null, 'not_cve'))).toBe('Not a CVE ID')
    expect(kevCellText(undefined)).toBe('No data')
  })

  it('shows the score as it is, and the other states in words', () => {
    expect(epssCellText(threat('listed', 0.97))).toBe('0.97')
    expect(epssCellText(threat('listed', 0.00043))).toBe('0.00043')
    expect(epssCellText(threat('listed', null, 'not_listed'))).toBe('Not listed')
    expect(epssCellText(threat('listed', null, 'no_data'))).toBe('No data')
    expect(epssCellText(threat('listed', null, 'not_cve'))).toBe('Not a CVE ID')
    expect(epssCellText(undefined)).toBe('No data')
  })
})

const source = (changes: Partial<ThreatSource> = {}): ThreatSource => ({
  status: 'loaded', as_of: '2026-11-10', age_days: 1, old: false, error: null, ...changes,
})
const NOT_LOADED = source({ status: 'not_loaded', as_of: null, age_days: null })

describe('the data status line', () => {
  it('says "KEV/EPSS data not loaded" when there is no data at all', () => {
    for (const data of [undefined, { kev: NOT_LOADED, epss: NOT_LOADED }]) {
      expect(threatStatusText(data)).toEqual({ text: 'KEV/EPSS data not loaded.', needsRefresh: true })
    }
  })

  it('gives the date and age of each file', () => {
    const data: ThreatData = { kev: source(), epss: source({ as_of: '2026-11-11', age_days: 0 }) }
    expect(threatStatusText(data)).toEqual({
      text:
        'Known exploited (CISA KEV) data of 2026-11-10 (1 day old). ' +
        'Exploit probability (EPSS) data of 2026-11-11 (today).',
      needsRefresh: false,
    })
  })

  it('says when data is old', () => {
    const data: ThreatData = { kev: source({ age_days: 9, old: true }), epss: source() }
    const status = threatStatusText(data)
    expect(status.text).toContain('(9 days old, old: run the refresh command)')
    expect(status.needsRefresh).toBe(true)
  })

  it('names the file that cannot be used and the one that is not loaded', () => {
    const data: ThreatData = {
      kev: source({ status: 'error', as_of: null, age_days: null, error: 'KEV file is not valid JSON' }),
      epss: NOT_LOADED,
    }
    expect(threatStatusText(data)).toEqual({
      text:
        'Known exploited (CISA KEV) data cannot be used: KEV file is not valid JSON. ' +
        'Exploit probability (EPSS) data not loaded.',
      needsRefresh: true,
    })
  })

  it('knows whether the KEV list is loaded, which the filter and the sort need', () => {
    expect(kevLoaded(undefined)).toBe(false)
    expect(kevLoaded({ kev: NOT_LOADED, epss: source() })).toBe(false)
    expect(kevLoaded({ kev: source({ status: 'error', error: 'x' }), epss: source() })).toBe(false)
    expect(kevLoaded({ kev: source(), epss: NOT_LOADED })).toBe(true)
  })
})

describe('the words for a package', () => {
  it('says how many of its CVEs are known exploited', () => {
    expect(packageKevText([finding('CVE-1', threat('listed', 0.9)), finding('CVE-2', threat('not_listed', 0.1))])).toBe('Yes, 1 of 2 CVEs')
    expect(packageKevText([finding('CVE-1', threat('listed', 0.9))])).toBe('Yes, 1 of 1 CVE')
  })

  it('tells "not listed", "not a CVE ID" and "no data" apart', () => {
    expect(packageKevText([finding('CVE-1', threat('not_listed', null))])).toBe('Not listed')
    expect(packageKevText([finding('GHSA-1', threat('not_cve', null, 'not_cve'))])).toBe('Not a CVE ID')
    expect(packageKevText([finding('CVE-1')])).toBe('No data')
    expect(packageKevText([])).toBe('No data')
    expect(packageEpssText([finding('CVE-1', threat('not_listed', null))])).toEqual({ text: 'Not listed', id: null })
    expect(packageEpssText([finding('CVE-1')])).toEqual({ text: 'No data', id: null })
  })

  it('gives the highest score with its CVE', () => {
    expect(packageEpssText([finding('CVE-1', threat('not_listed', 0.2)), finding('CVE-2', threat('listed', 0.7))])).toEqual({ text: '0.7', id: 'CVE-2' })
  })
})
