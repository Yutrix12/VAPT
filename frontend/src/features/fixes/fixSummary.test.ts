import { describe, expect, it } from 'vitest'
import type {
  AnalyzeResult,
  Finding,
  FixAdvice,
  FixState,
  License,
  Misconfiguration,
  OtherAdvice,
  OtherFixState,
  PackageGroup,
  Secret,
  Severity,
} from '../../api/types'
import { SEVERITIES } from '../../api/types'
import { buildRows } from '../report/rows'
import { defaultFilters, type FilterState } from '../filters/filterState'
import { buildFixSummary, codeBlock, codeSpan, escapeMarkdown, summaryFileName } from './fixSummary'

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
    has_unfixed: findings.some((f) => f.fixed_version === null), findings, fix_commands: [], fix_commands_note: null,
  }
}

const openssl = group('openssl', [finding('CVE-1', 'CRITICAL', '3.5.4'), finding('CVE-2', 'LOW', null)], ['3.5.4'])
const zlib = group('zlib', [finding('CVE-3', 'HIGH', '1.3')], ['1.3'])
const curl = group(`cu${RLO}rl`, [finding('CVE-4', 'MEDIUM', '8.0')], ['8.0'])

const result: AnalyzeResult = {
  report: {
    file_name: 'image.json', file_sha256: 'x', report_format: 'Trivy JSON', not_in_format: [],
    schema_version: 2, trivy_version: '0.76.2',
    created_at: '2026-11-06T04:15:32Z', artifact_name: 'python:3.9-slim', artifact_type: 'container_image',
    os_family: 'debian', os_name: '13.1', repo_url: null, branch: null, commit: null,
    misconfig_count: 0, secret_count: 0,
  },
  summary: {
    total: 4, by_severity: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 1, UNKNOWN: 0 },
    by_status: { fixed: 4 }, unique_vuln_ids: 4, unique_packages: 3, without_fixed_version: 1,
    distinct_fingerprints: 4,
    by_kind: { vulnerability: 4, misconfiguration: 0, secret: 0, license: 0 },
    misconfig_passed: 0, misconfig_exceptions: 0,
  },
  package_groups: [openssl, zlib, curl],
  misconfigurations: [], secrets: [], licenses: [], secret_fix_steps: [],
}

function advice(changes: Partial<FixAdvice>): FixAdvice {
  return {
    status: 'verified', target_version: '3.5.4', unverified_version: null, trivy_fixed_versions: ['3.5.4'],
    mitigation_only: false, cves_without_fix: 1, summary: 'Upgrade [now](https://evil.example).',
    solutions: ['Upgrade openssl.\nThen restart.', 'Use a newer base image.'], mitigations: ['Limit exposure.'],
    unsafe_commands_removed: 0, commands: ['apt-get install openssl', 'echo ```'],
    risk_notes: 'Restart services.', disclaimer: 'AI suggestion: verify before applying',
    ...changes,
  }
}

function summaryOf(fixes: Map<string, FixState>, severities: ReadonlySet<Severity> = new Set(SEVERITIES)) {
  const filters = { ...defaultFilters(), severities }
  return buildFixSummary({
    result,
    rows: buildRows(result, filters),
    otherFixFor: () => undefined,
    filters,
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
    expect(text).toContain('- Report format: Trivy JSON')
    expect(text).toContain('4 findings in 3 packages: 1 Critical, 1 High, 1 Medium, 1 Low; 0 Unknown (not rated)')
    expect(text).toContain('Filters: none. This summary lists all 3 items.')
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
    expect(text).toContain('- AI answer: Verified fix')
    expect(text).toContain('- Solutions:')
    expect(text).toContain('  1. Upgrade openssl. Then restart.')
    expect(text).toContain('  2. Use a newer base image.')
    expect(text).toContain('- Mitigations until a fix exists:')
    expect(text).toContain('  - Limit exposure.')
    expect(text).toContain('AI-suggested, verify before running (this app never runs them):\n\n````\napt-get install openssl\necho ```\n````')
  })

  it('marks a version that is not Trivy’s as not a fix', () => {
    expect(text).toContain("- AI verdict: the AI suggested `9.9`, which is not one of Trivy's fixed versions, so it is not a fix")
  })

  it('still lists packages without an AI answer, with their fixed versions', () => {
    expect(text).toContain('## 3. cu\\\\u202Erl\n')
    expect(text).toContain('- Fixed versions: `8.0`')
    expect(text).toContain('- AI explanation: not requested yet')
  })

  it('says "1 item", not "all 1 item", for a one-item report', () => {
    const single = { ...result, package_groups: [zlib] }
    const text = buildFixSummary({
      result: single, rows: buildRows(single, defaultFilters()), otherFixFor: () => undefined,
      filters: defaultFilters(), fixFor: () => undefined, model: null,
    })
    expect(text).toContain('Filters: none. This summary lists 1 item.')
    expect(text).toContain('- AI model used: none connected yet')
  })

  it('writes the repository line like the page, also without git details', () => {
    const repo = { ...result, report: { ...result.report, artifact_type: 'repository' } }
    const text = buildFixSummary({
      result: repo, rows: [], otherFixFor: () => undefined, filters: defaultFilters(), fixFor: () => undefined, model: null,
    })
    expect(text).toContain('- Repository: No git details in the report')
  })

  it('says which fields a report format does not carry', () => {
    const lacking = {
      ...result,
      report: { ...result.report, report_format: 'Trivy table', created_at: null, os_family: null, os_name: null,
                not_in_format: ['created_at', 'os', 'status'] },
    }
    const text = buildFixSummary({
      result: lacking, rows: [], otherFixFor: () => undefined, filters: defaultFilters(), fixFor: () => undefined, model: null,
    })
    expect(text).toContain('- Report format: Trivy table')
    expect(text).toContain('Scan date: not in this format.')
    expect(text).toContain('operating system: not in this format')
  })

  it('names the artifact and the Trivy version "not in this format" for a table, and lists what is missing', () => {
    const table = {
      ...result,
      report: { ...result.report, report_format: 'Trivy text (table)', artifact_name: null, artifact_type: null,
                trivy_version: null, created_at: null,
                not_in_format: ['artifact_name', 'artifact_type', 'trivy_version', 'created_at', 'cvss_score'] },
    }
    const text = buildFixSummary({
      result: table, rows: [], otherFixFor: () => undefined, filters: defaultFilters(), fixFor: () => undefined, model: null,
    })
    expect(text).toContain('# Fix summary: not in this format')
    expect(text).toContain('Trivy version: not in this format.')
    expect(text).toContain('Artifact type: not in this format;')
    expect(text).toContain('- Not in this format: CVSS scores')
  })

  it('names every filter that is on: search, kind, severity, status and fix available', () => {
    const filters: FilterState = {
      search: 'open*ssl', kind: 'vulnerability', severities: new Set<Severity>(['HIGH']), status: 'fixed', fixOnly: true,
    }
    const text = buildFixSummary({ result, rows: [], otherFixFor: () => undefined, filters, fixFor: () => undefined, model: null })
    expect(text).toContain(
      'Filters: search `open*ssl`; kind Vulnerabilities; severity High; status `fixed`; fix available.')
  })

  it('keeps hidden characters in the search text out of the summary', () => {
    const filters = { ...defaultFilters(), search: `a${RLO}b` }
    const text = buildFixSummary({ result, rows: [], otherFixFor: () => undefined, filters, fixFor: () => undefined, model: null })
    expect(text).not.toContain(RLO)
  })

  it('says "no items" for a report without any', () => {
    const empty = { ...result, package_groups: [] }
    const text = buildFixSummary({
      result: empty, rows: [], otherFixFor: () => undefined, filters: defaultFilters(), fixFor: () => undefined, model: null,
    })
    expect(text).toContain('Filters: none. This summary lists no items.')
  })

  it('follows the filters and says which ones were on', () => {
    const highOnly = summaryOf(fixes, new Set<Severity>(['HIGH']))
    expect(highOnly).toContain('Filters: severity High. This summary lists 1 of 3 items.')
    expect(highOnly).toContain('## 1. zlib')
    expect(highOnly).not.toMatch(/^## \d+\. openssl$/m) // no section for the filtered-out package
  })
})

describe('buildFixSummary for every kind and the built commands', () => {
  const misconfiguration: Misconfiguration = {
    fingerprint: 'm', target: 'Dockerfile', misconf_type: 'dockerfile', check_type: null, check_id: 'DS-0002',
    title: 'Image user should not be root', description: 'Root is risky.', resolution: 'Add a USER line.',
    severity: 'HIGH', status: 'FAIL', primary_url: 'https://example.invalid/ds-0002', references: [], resource: null,
    start_line: 3, end_line: 4,
  }
  const secret: Secret = {
    fingerprint: 's', target: 'deploy.sh', rule_id: 'aws-access-key-id', category: 'AWS', severity: 'CRITICAL',
    title: 'AWS Access Key ID', start_line: 3, end_line: 3,
  }
  const license: License = {
    fingerprint: 'l', target: 'Java', license_class: 'license', pkg_name: 'org.a:a', file_path: null, name: 'EPL-1.0',
    category: 'reciprocal', severity: 'MEDIUM', confidence: null, link: 'https://example.invalid/epl',
  }
  const withCommands: PackageGroup = {
    ...openssl,
    fix_commands: [
      { label: 'Fixed version 3.5.4', lines: ['apt-get update', 'apt-get install --only-upgrade openssl=3.5.4'] },
      { label: 'Fixed version 3.5.5', lines: ['apt-get update', 'apt-get install --only-upgrade openssl=3.5.5'] },
    ],
    fix_commands_note: 'Trivy lists several fixed versions (often one per release). Use the one that fits your release.',
  }
  const everything: AnalyzeResult = {
    ...result,
    summary: { ...result.summary, by_kind: { vulnerability: 4, misconfiguration: 1, secret: 1, license: 1 } },
    package_groups: [withCommands, { ...zlib, fix_commands_note: 'No command is built for alpine: its syntax is not verified.' }, curl],
    misconfigurations: [misconfiguration],
    secrets: [secret],
    licenses: [license],
    secret_fix_steps: ['Revoke or rotate the credential.', 'Remove it from the code.'],
  }
  const advice: OtherAdvice = {
    kind: 'secret', status: 'solution_options', summary: 'Revoke it now.', solutions: ['Revoke the key.', 'Rotate the key.'],
    mitigations: ['Watch the logs.'], risk_notes: 'It may be used already.', disclaimer: 'AI suggestion: verify before applying',
  }

  function build(otherFixes: Map<string, OtherFixState> = new Map(), filters = defaultFilters(), data = everything) {
    return buildFixSummary({
      result: data,
      rows: buildRows(data, filters),
      filters,
      fixFor: () => undefined,
      otherFixFor: (row) => otherFixes.get(row.key),
      model: 'qwen3:8b',
      locale: 'en-GB',
      timeZone: 'UTC',
    })
  }

  it('describes the report with the counts of all kinds', () => {
    expect(build()).toContain('7 findings: 4 vulnerabilities in 3 packages, 1 misconfiguration, 1 secret, 1 license')
  })

  it('has one section per finding, worst first, whatever its kind', () => {
    const headings = build().split('\n').filter((line) => line.startsWith('## '))
    expect(headings).toEqual([
      '## 1. openssl',
      '## 2. aws-access-key-id (AWS)',
      '## 3. zlib',
      '## 4. DS-0002: Image user should not be root',
      '## 5. cu\\\\u202Erl', // the hidden character shows as a visible code (its backslash is escaped)
      '## 6. EPL-1.0',
    ])
  })

  it('shows the commands built by code for a package, with their labels and note', () => {
    const text = build()
    expect(text).toContain("Fix commands, built by code from Trivy's fixed versions (this app never runs them):")
    expect(text).toContain('Fixed version 3.5.4\n\n```\napt-get update\napt-get install --only-upgrade openssl=3.5.4\n```')
    expect(text).toContain('Trivy lists several fixed versions')
  })

  it('says why a package has no command', () => {
    const text = build()
    expect(text).toContain('- Fix commands: No command is built for alpine: its syntax is not verified.')
  })

  it('lists a misconfiguration with what is wrong and Trivy fix text', () => {
    const text = build()
    expect(text).toContain('- Kind: Misconfiguration')
    expect(text).toContain('- Where: Dockerfile, lines 3 to 4')
    expect(text).toContain('- What is wrong: Root is risky.')
    expect(text).toContain("- Trivy's fix: Add a USER line.")
  })

  it('says when a misconfiguration has no fix text, or its format cannot carry it', () => {
    const none = { ...everything, misconfigurations: [{ ...misconfiguration, resolution: null }] }
    expect(build(new Map(), defaultFilters(), none)).toContain("- Trivy's fix: none in the report")
    const table = { ...none, report: { ...none.report, not_in_format: ['resolution'] } }
    expect(build(new Map(), defaultFilters(), table)).toContain("- Trivy's fix: not in this format")
  })

  it('lists a secret with its place and the fixed steps, and says its value is never in the file', () => {
    const text = build()
    expect(text).toContain('- Kind: Secret')
    expect(text).toContain('- Where: deploy.sh, line 3')
    expect(text).toContain('- How to fix it:\n  1. Revoke or rotate the credential.\n  2. Remove it from the code.')
    expect(text).toContain("The secret's value is never part of this file.")
  })

  it('lists a license and points to the legal team without judging it', () => {
    const text = build()
    expect(text).toContain('- Kind: License')
    expect(text).toContain('- Category: reciprocal')
    expect(text).toContain('Ask your legal or compliance team')
  })

  it('adds the AI answer for a finding that is not a package, in its state', () => {
    const text = build(new Map([['secret:0', { state: 'done', advice }]]))
    expect(text).toContain('- AI answer: Solution options')
    expect(text).toContain('- Solutions:\n  1. Revoke the key.\n  2. Rotate the key.')
    expect(text).toContain('- Mitigations until it is fixed:\n  - Watch the logs.')
    expect(text).toContain('- Risks: It may be used already.')
  })

  it('says what became of an AI request for such a finding', () => {
    expect(build()).toContain('- AI explanation: not requested yet')
    expect(build(new Map([['secret:0', { state: 'error', message: 'No AI' }]]))).toContain('- AI explanation failed: No AI')
    expect(build(new Map([['secret:0', { state: 'loading', startedAt: 1 }]]))).toContain('still running when this summary was made')
  })

  it('follows the filters for every kind and names them', () => {
    const text = build(new Map(), { ...defaultFilters(), kind: 'secret' })
    expect(text).toContain('Filters: kind Secrets. This summary lists 1 of 6 items.')
    expect(text).toContain('## 1. aws-access-key-id (AWS)')
    expect(text).not.toContain('DS-0002')
  })
})
