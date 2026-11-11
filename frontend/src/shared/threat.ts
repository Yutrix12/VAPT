// Known exploited (CISA KEV) and exploit probability (EPSS): the words and the small rules (no React here).
// The values come from the backend's local data files, never from the AI, and are never guessed.
import type { Finding, FindingThreat, ThreatData, ThreatSource, ThreatState } from '../api/types'

export const KEV_LABEL = 'Known exploited (CISA KEV)'
export const EPSS_LABEL = 'Exploit probability (EPSS)'

/** True when the package was checked against the local KEV/EPSS data (the backend leaves the field out otherwise). */
export function hasThreatData(group: { findings: readonly Finding[] }): boolean {
  return group.findings.some((finding) => finding.threat !== undefined)
}

/** True when the loaded KEV list holds this CVE. */
export function isKnownExploited(finding: Finding): boolean {
  return finding.threat?.kev === 'listed'
}

/** How many of the findings are on the KEV list. */
export function kevCount(findings: readonly Finding[]): number {
  return findings.filter(isKnownExploited).length
}

/** The highest EPSS score among the findings and its CVE ID; null when none has a score. */
export function highestEpss(findings: readonly Finding[]): { value: number; id: string | null } | null {
  let best: { value: number; id: string | null } | null = null
  for (const finding of findings) {
    const { threat } = finding
    if (threat?.epss_state !== 'listed' || threat.epss === null) continue
    if (best === null || threat.epss > best.value) best = { value: threat.epss, id: finding.vuln_id }
  }
  return best
}

const STATE_WORDS: Record<Exclude<ThreatState, 'listed'>, string> = {
  not_listed: 'Not listed',
  no_data: 'No data',
  not_cve: 'Not a CVE ID',
}

/** KEV for one CVE: Yes, Not listed (in the loaded list), No data (no file) or Not a CVE ID. */
export function kevCellText(threat: FindingThreat | undefined): string {
  const state = threat?.kev ?? 'no_data'
  return state === 'listed' ? 'Yes' : STATE_WORDS[state]
}

/** EPSS for one CVE: the score as it is, or the same words. */
export function epssCellText(threat: FindingThreat | undefined): string {
  const state = threat?.epss_state ?? 'no_data'
  if (state === 'listed') return threat?.epss == null ? STATE_WORDS.no_data : String(threat.epss)
  return STATE_WORDS[state]
}

/** True when the KEV list is loaded, so the "Known exploited" filter and sort mean something. */
export function kevLoaded(data: ThreatData | undefined): boolean {
  return data?.kev.status === 'loaded'
}

function ageText(days: number | null): string {
  if (days === null) return 'age unknown'
  if (days <= 0) return 'today'
  return days === 1 ? '1 day old' : `${days} days old`
}

function sourceText(label: string, source: ThreatSource): string {
  switch (source.status) {
    case 'not_loaded':
      return `${label} data not loaded.`
    case 'error':
      return `${label} data cannot be used: ${source.error ?? 'unknown error'}.`
    case 'loaded': {
      const age = source.old ? `${ageText(source.age_days)}, old` : ageText(source.age_days)
      return `${label} data of ${source.as_of ?? 'unknown date'} (${age}).`
    }
  }
}

/** The line that says what data the KEV/EPSS values come from, or that there is none. */
export function threatStatusText(data: ThreatData | undefined): { text: string; needsRefresh: boolean } {
  if (data === undefined || (data.kev.status === 'not_loaded' && data.epss.status === 'not_loaded')) {
    return { text: 'KEV/EPSS data not loaded.', needsRefresh: true }
  }
  return {
    text: `${sourceText(KEV_LABEL, data.kev)} ${sourceText(EPSS_LABEL, data.epss)}`,
    needsRefresh: [data.kev, data.epss].some((source) => source.status !== 'loaded' || source.old),
  }
}

/** When no CVE of a package is on the list or has a score: not listed, not a CVE ID, or no data. */
function missingWords(states: (ThreatState | undefined)[]): string {
  if (states.includes('not_listed')) return STATE_WORDS.not_listed
  if (states.length > 0 && states.every((state) => state === 'not_cve')) return STATE_WORDS.not_cve
  return STATE_WORDS.no_data
}

/** KEV for a package: "Yes, 1 of 2 CVEs" if any of its CVEs is on the list, else the reason there is none. */
export function packageKevText(findings: readonly Finding[]): string {
  const count = kevCount(findings)
  if (count > 0) return `Yes, ${count} of ${findings.length} ${findings.length === 1 ? 'CVE' : 'CVEs'}`
  return missingWords(findings.map((finding) => finding.threat?.kev))
}

/** The highest EPSS score of a package (and its CVE), or the reason there is none. */
export function packageEpssText(findings: readonly Finding[]): { text: string; id: string | null } {
  const best = highestEpss(findings)
  if (best !== null) return { text: String(best.value), id: best.id }
  return { text: missingWords(findings.map((finding) => finding.threat?.epss_state)), id: null }
}
