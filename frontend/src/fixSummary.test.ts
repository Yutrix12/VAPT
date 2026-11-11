import { describe, expect, it } from 'vitest'
import { buildFixSummary, codeBlock, codeSpan, escapeMarkdown, summaryFileName } from './fixSummary'
import { filterGroups } from './reportLogic'
import type { AnalyzeResult, Finding, FixAdvice, FixState, PackageGroup, Severity } from './types'
import { SEVERITIES } from './types'

const RLO = String.fromCodePoint(0x202e) // right-to-left override: hidden

describe('escapeMarkdown', () => {
  it('stops report or AI text from becoming links, HTML or formatting', () => {
    expect(escapeMarkdown('see [this](https://evil.example) <b>x</b> *y* a|b_c `d` ~e! &amp;'))
      .toBe('see \\[this\\](https\\:\\/\\/evil.example) \\<b\\>x\\</b\\> \\*y\\* a\\|b\\_c \\`d\\` \\~e\\! \\&amp;')
    expect(escapeMarkdown('go to www.evil.example')).toBe('go to www\\.evil.example')
    expect(escapeMarkdown('see_www.evil.example')).toBe('see\\_www\\.evil.example')
  })

  it('stops e-mail links, @mentions, math and lost heading characters', () => {
    expect(escapeMarkdown('mail security@evil.example or ping @admin')).toBe(
      'mail security\\@evil.example or ping \\@admin')
    expect(escapeMarkdown('set $HOME and $PATH')).toBe('set \\$HOME and \\$PATH')
    expect(escapeMarkdown('build #')).toBe('build \\#')
  })

  it('keeps everything on one line, so text cannot start a heading or list', () => {
    expect(escapeMarkdown('fine\n## Fake heading\n- item')).toBe('fine \\#\\# Fake heading - item')
  })

  it('shows hidden characters as codes, and keeps the backslash visible', () => {
    expect(escapeMarkdown(`open${RLO}ssl`)).toBe('open\\\\u202Essl')
  })
})

describe('codeSpan and codeBlock', () => {
  it('wraps text in a code span that its own backticks cannot close', () => {
    expect(codeSpan('3.5.4-1~deb13u2')).toBe('`3.5.4-1~deb13u2`')
    expect(codeSpan('a`b')).toBe('``a`b``')
    expect(codeSpan('`x')).toBe('`` `x ``')
    expect(codeSpan('')).toBe('(empty)')
  })

  it('fences commands with more backticks than any command contains', () => {
    expect(codeBlock(['apt-get update', 'echo ```'])).toBe('````\napt-get update\necho ```\n````')
    expect(codeBlock(['pip install -U pypdf'])).toBe('```\npip install -U pypdf\n```')
  })
})

describe('summaryFileName', () => {
  it('names the file after the report, with safe characters only', () => {
    expect(summaryFileName('image.json')).toBe('fix-summary-image.md')
    expect(summaryFileName('my scan <1>.JSON')).toBe('fix-summary-my_scan__1_.md')
    expect(summaryFileName('.json')).toBe('fix-summary-report.md')
  })
})

function finding(id: string, severity: Severity, fixed: string | null): Finding {
  return {
    fingerprint: id, target: 'python:3.9-slim (debian 13.1)', vuln_class: 'os-pkgs', vuln_type: 'debian',
    vuln_id: id, pkg_name: 'x', installed_version: '1.0', fixed_version: fixed, status: 'fixed',
    severity, title: 'a bug', cvss_score: null, primary_url: null, published_date: null,
  }
}

function group(name: string, findings: Finding[], fixed: string[]): PackageGroup {
  return {
    target: 'python:3.9-slim (debian 13.1)', pkg_name: name, installed_version: '3.5.1',
    finding_count: findings.length, worst_severity: findings[0].severity, fixed_versions: fixed,
    has_unfixed: findings.some((f) => f.fixed_version === null), findings,
  }
}

const openssl = group('openssl', [finding('CVE-1', 'CRITICAL', '3.5.4'), finding('CVE-2', 'LOW', null)], ['3.5.4'])
const zlib = group('zlib', [finding('CVE-3', 'HIGH', '1.3')], ['1.3'])
const curl = group(`cu${RLO}rl`, [finding('CVE-4', 'MEDIUM', '8.0')], ['8.0'])

const result: AnalyzeResult = {
  report: {
    file_name: 'image.json', file_sha256: 'x', schema_version: 2, trivy_version: '0.76.2',
    created_at: '2026-11-06T04:15:32Z', artifact_name: 'python:3.9-slim', artifact_type: 'container_image',
    os_family: 'debian', os_name: '13.1', repo_url: null, branch: null, commit: null,
    misconfig_count: 0, secret_count: 0,
  },
  summary: {
    total: 4, by_severity: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0 },
    by_status: { fixed: 4 }, unique_vuln_ids: 4, unique_packages: 3, without_fixed_version: 1,
    distinct_fingerprints: 4,
  },
  package_groups: [openssl, zlib, curl],
}

function advice(changes: Partial<FixAdvice>): FixAdvice {
  return {
    status: 'verified', target_version: '3.5.4', unverified_version: null, trivy_fixed_versions: ['3.5.4'],
    mitigation_only: false, cves_without_fix: 1, summary: 'Upgrade [now](https://evil.example).',
    recommended_action: 'Upgrade openssl.\nThen restart.', commands: ['apt-get install openssl', 'echo ```'],
    risk_notes: 'Restart services.', disclaimer: 'AI suggestion: verify before applying',
    ...changes,
  }
}

function summaryOf(fixes: Map<string, FixState>, severities: ReadonlySet<Severity> = new Set(SEVERITIES)) {
  return buildFixSummary({
    result,
    shown: filterGroups(result.package_groups, severities, ''),
    severities,
    status: '',
    fixFor: (g) => fixes.get(g.pkg_name ?? ''),
    model: 'qwen3:8b',
    locale: 'en-GB',
    timeZone: 'UTC',
  })
}

describe('buildFixSummary', () => {
  const fixes = new Map<string, FixState>([
    ['openssl', { state: 'done', advice: advice({}) }],
    ['zlib', { state: 'done', advice: advice({ status: 'unverified', target_version: null, unverified_version: '9.9', cves_without_fix: 0, commands: [] }) }],
  ])
  const text = summaryOf(fixes)

  it('starts with what was scanned, the counts and the AI warning', () => {
    expect(text.startsWith('# Fix summary: python:3.9-slim\n')).toBe(true)
    expect(text).toContain('- Report file: `image.json`. Scan date: 6 Nov 2026, 04:15. Trivy version: 0.76.2.')
    expect(text).toContain('- Artifact type: Container image; operating system: debian 13.1')
    expect(text).toContain('4 findings in 3 packages: 1 Critical, 1 High, 1 Medium, 1 Low; 0 Unknown (not rated)')
    expect(text).toContain('Filters: none. This summary lists all 3 packages.')
    expect(text).toContain('- AI model used: `qwen3:8b`')
    expect(text).toContain('> AI suggestions: verify before applying.')
  })

  it('lists a verified package with its fixed versions, the verdict, the advice and the commands', () => {
    expect(text).toContain('## 1. openssl\n')
    expect(text).toContain('- Installed version: `3.5.1`')
    expect(text).toContain('- Findings: 2 (highest severity: Critical)')
    expect(text).toContain('- Fixed versions: `3.5.4` (some vulnerabilities have no fixed version yet)')
    expect(text).toContain("- AI verdict: recommended upgrade `3.5.4` (one of Trivy's fixed versions)")
    expect(text).toContain('- 1 vulnerability in this package has no fixed version yet and stays open after any upgrade.')
    expect(text).toContain('- Summary: Upgrade \\[now\\](https\\:\\/\\/evil.example).')
    expect(text).toContain('- What to do: Upgrade openssl. Then restart.')
    expect(text).toContain('AI-suggested commands (verify before running; never run by this app):\n\n````\napt-get install openssl\necho ```\n````')
  })

  it('marks a version that is not Trivy’s as not a fix', () => {
    expect(text).toContain("- AI verdict: the AI suggested `9.9`, which is not one of Trivy's fixed versions, so it is not a fix")
  })

  it('still lists packages without an AI answer, with their fixed versions', () => {
    expect(text).toContain('## 3. cu\\\\u202Erl\n')
    expect(text).toContain('- Fixed versions: `8.0`')
    expect(text).toContain('- AI explanation: not requested yet')
  })

  it('says "1 package", not "all 1 package", for a one-package report', () => {
    const single = { ...result, package_groups: [zlib] }
    const text = buildFixSummary({
      result: single, shown: filterGroups(single.package_groups, new Set(SEVERITIES), ''),
      severities: new Set(SEVERITIES), status: '', fixFor: () => undefined, model: null,
    })
    expect(text).toContain('Filters: none. This summary lists 1 package.')
    expect(text).toContain('- AI model used: none connected yet')
  })

  it('writes the repository line like the page, also without git details', () => {
    const repo = { ...result, report: { ...result.report, artifact_type: 'repository' } }
    const text = buildFixSummary({
      result: repo, shown: [], severities: new Set(SEVERITIES), status: '', fixFor: () => undefined, model: null,
    })
    expect(text).toContain('- Repository: No git details in the report')
  })

  it('says "no packages" for a report without any', () => {
    const empty = { ...result, package_groups: [] }
    const text = buildFixSummary({
      result: empty, shown: [], severities: new Set(SEVERITIES), status: '', fixFor: () => undefined, model: null,
    })
    expect(text).toContain('Filters: none. This summary lists no packages.')
  })

  it('follows the filters and says which ones were on', () => {
    const highOnly = summaryOf(fixes, new Set<Severity>(['HIGH']))
    expect(highOnly).toContain('Filters: severity High. This summary lists 1 of 3 packages.')
    expect(highOnly).toContain('## 1. zlib')
    expect(highOnly).not.toMatch(/^## \d+\. openssl$/m) // no section for the filtered-out package
  })
})
