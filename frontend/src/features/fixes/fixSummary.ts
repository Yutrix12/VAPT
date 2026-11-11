// The "fix summary" Markdown file, built from what the page shows (no React).
//
// Report text and AI text are untrusted, and the file is opened in other
// programs (VS Code, GitHub, wikis). Every such text goes through
// escapeMarkdown, codeSpan or codeBlock, so it can never become a link,
// HTML, a heading or formatting, and hidden characters show as codes.
import {
  SEVERITIES,
  type AnalyzeResult,
  type FixAdvice,
  type FixState,
  type Kind,
  type OtherAdvice,
  type OtherFixState,
  type PackageGroup,
} from '../../api/types'
import {
  NOT_IN_FORMAT,
  artifactTypeLabel,
  fieldOrNotInFormat,
  kindLabel,
  lineText,
  misconfigurationName,
  missingFieldsText,
  overviewText,
  secretName,
} from '../../shared/reportText'
import { RATED_SEVERITIES, severityLabel } from '../../shared/severity'
import { countText, formatScanDate, KEEP_LINE_BREAKS, visibleText } from '../../shared/text'
import { EPSS_LABEL, KEV_LABEL, packageEpssText, packageKevText, threatStatusText } from '../../shared/threat'
import { ALL_STATUSES } from '../filters/filterGroups'
import { ALL_KINDS, type FilterState } from '../filters/filterState'
import { severityCounts, totalRows, type OtherRow, type Row } from '../report/rows'
import { answerState, openAfterUpgradeText, otherAnswerState } from './fixLogic'

/** Line breaks become spaces, so text cannot start a heading or a list. */
function oneLine(text: string): string {
  return text.replace(/\s*[\r\n]+\s*/g, ' ')
}

/** Plain text for Markdown: no links, HTML or formatting; hidden characters as codes. */
export function escapeMarkdown(text: string): string {
  return (
    visibleText(oneLine(text))
      // Backslash-escape the characters that start formatting, links,
      // images, HTML, entities, table cells, e-mail links and @mentions
      // (@), math ($) and heading marks (#, which a heading would drop).
      .replace(/[\\`*_[\]<>|~!&@$#]/g, '\\$&')
      // Stop automatic links ("https://..." and "www.", even after "_").
      .replace(/:\/\//g, '\\:\\/\\/')
      .replace(/www\./gi, (match) => `${match.slice(0, 3)}\\.`)
  )
}

/** The longest run of backticks in the text (0 if none). */
function longestBacktickRun(text: string): number {
  return Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length))
}

/** Inline code (versions, names): fenced with more backticks than the text has. */
export function codeSpan(text: string): string {
  const content = visibleText(oneLine(text))
  if (content === '') return '(empty)' // two backticks alone are not a code span
  const fence = '`'.repeat(longestBacktickRun(content) + 1)
  const pad = content.startsWith('`') || content.endsWith('`') ? ' ' : ''
  return `${fence}${pad}${content}${pad}${fence}`
}

/** A code block (commands) that no line inside it can close early. */
export function codeBlock(lines: readonly string[]): string {
  const content = lines.map((line) => visibleText(line, KEEP_LINE_BREAKS)).join('\n')
  const fence = '`'.repeat(Math.max(3, longestBacktickRun(content) + 1))
  return `${fence}\n${content}\n${fence}`
}

/** "fix-summary-image.md" for image.json: only safe characters. */
export function summaryFileName(reportFileName: string): string {
  const stem = reportFileName
    .replace(/\.json$/i, '')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 100)
  return `fix-summary-${stem || 'report'}.md`
}

export interface SummaryInput {
  result: AnalyzeResult
  rows: Row[] // every finding the filters show, worst first, whatever its kind
  filters: FilterState // the filters that were on; the summary says which
  fixFor: (group: PackageGroup) => FixState | undefined
  otherFixFor: (row: OtherRow) => OtherFixState | undefined
  model: string | null // the model the answers came from (last successful check)
  locale?: string // for tests; the browser's own by default
  timeZone?: string
}

function scannedLine(result: AnalyzeResult): string {
  const { report } = result
  if (report.artifact_type === 'repository') {
    const parts = [report.repo_url, report.branch, report.commit].filter((part): part is string => Boolean(part))
    return `- Repository: ${parts.length > 0 ? parts.map(codeSpan).join(', ') : 'No git details in the report'}`
  }
  const os = [report.os_family, report.os_name].filter(Boolean).join(' ')
  return (
    `- Artifact type: ${escapeMarkdown(fieldOrNotInFormat(report, 'artifact_type', artifactTypeLabel(report.artifact_type)))}; ` +
    `operating system: ${escapeMarkdown(fieldOrNotInFormat(report, 'os', os || 'unknown'))}`
  )
}

function countsLine(result: AnalyzeResult): string {
  const counts = severityCounts(result) // all kinds together, like the page
  const rated = RATED_SEVERITIES.map((s) => `${counts[s]} ${severityLabel(s)}`).join(', ')
  const headline = overviewText(result.summary.by_kind, result.summary.unique_packages)
  return `- ${headline}: ${rated}; ${counts.UNKNOWN} Unknown (not rated)`
}

const KIND_PLURALS: Record<Kind, string> = {
  vulnerability: 'Vulnerabilities',
  misconfiguration: 'Misconfigurations',
  secret: 'Secrets',
  license: 'Licenses',
}

function filtersLine(input: SummaryInput): string {
  const { filters: on } = input
  const filters: string[] = []
  if (on.search.trim() !== '') filters.push(`search ${codeSpan(on.search.trim())}`)
  if (on.kind !== ALL_KINDS) filters.push(`kind ${KIND_PLURALS[on.kind]}`)
  if (on.severities.size < SEVERITIES.length) {
    const shown = SEVERITIES.filter((s) => on.severities.has(s)).map(severityLabel)
    filters.push(shown.length > 0 ? `severity ${shown.join(', ')}` : 'no severity')
  }
  if (on.status !== ALL_STATUSES) filters.push(`status ${codeSpan(on.status)}`)
  if (on.fixOnly) filters.push('fix available')
  if (on.kevOnly) filters.push('known exploited only')
  const total = totalRows(input.result)
  let listed = `${input.rows.length} of ${countText(total, 'item')}`
  if (total === 0) listed = 'no items'
  else if (input.rows.length === total) listed = total === 1 ? '1 item' : `all ${countText(total, 'item')}`
  return `- Filters: ${filters.length > 0 ? filters.join('; ') : 'none'}. This summary lists ${listed}.`
}

function orderLine(input: SummaryInput): string {
  return `- Order: ${input.filters.sort === 'kev' ? 'known exploited first' : 'Trivy severity'}.`
}

/** Both values for a package, when any KEV/EPSS data was loaded (else the header says there is none). */
function threatLines(group: PackageGroup, loaded: boolean): string[] {
  if (!loaded) return []
  const epss = packageEpssText(group.findings)
  return [
    `- ${KEV_LABEL}: ${packageKevText(group.findings)}`,
    `- ${EPSS_LABEL}: ${epss.id === null ? epss.text : `highest ${epss.text} (${codeSpan(epss.id)})`}`,
  ]
}

function trivyFixText(group: PackageGroup): string {
  if (group.fixed_versions.length === 0) return 'no fixed version yet'
  const versions = group.fixed_versions.map(codeSpan).join(', ')
  return group.has_unfixed ? `${versions} (some vulnerabilities have no fixed version yet)` : versions
}

function verdictText(advice: FixAdvice): string {
  switch (advice.status) {
    case 'verified':
      return `recommended upgrade ${codeSpan(advice.target_version ?? '')} (one of Trivy's fixed versions)`
    case 'unverified':
      return (
        `the AI suggested ${codeSpan(advice.unverified_version ?? '')}, ` +
        "which is not one of Trivy's fixed versions, so it is not a fix"
      )
    case 'no_version_suggested':
      return "the AI named no version; use one of Trivy's fixed versions"
    case 'no_fix_available':
      return 'Trivy lists no fixed version yet; the advice below covers mitigations only'
  }
}

function adviceLines(advice: FixAdvice): string[] {
  const lines = [`- AI verdict: ${verdictText(advice)}`]
  if (advice.cves_without_fix > 0) lines.push(`- ${openAfterUpgradeText(advice.cves_without_fix)}`)
  lines.push(`- AI answer: ${answerState(advice.status)}`, `- Summary: ${escapeMarkdown(advice.summary)}`)
  if (advice.solutions.length > 0) {
    lines.push('- Solutions:', ...advice.solutions.map((text, index) => `  ${index + 1}. ${escapeMarkdown(text)}`))
  }
  if (advice.mitigations.length > 0) {
    lines.push('- Mitigations until a fix exists:', ...advice.mitigations.map((text) => `  - ${escapeMarkdown(text)}`))
  }
  lines.push(`- Risks: ${escapeMarkdown(advice.risk_notes)}`)
  if (advice.unsafe_commands_removed > 0) {
    lines.push(`- ${countText(advice.unsafe_commands_removed, 'AI command')} not shown: it skips a safety check`)
  }
  return lines
}

/** The AI's own commands as a code block, after the bullet list (a block would split the list). */
function aiCommandLines(fix: FixState | undefined): string[] {
  if (fix?.state !== 'done' || fix.advice.commands.length === 0) return []
  return ['', 'AI-suggested, verify before running (this app never runs them):', '', codeBlock(fix.advice.commands)]
}

function aiLines(fix: FixState | undefined): string[] {
  if (fix === undefined) return ['- AI explanation: not requested yet']
  switch (fix.state) {
    case 'queued':
    case 'loading':
      return ['- AI explanation: still running when this summary was made']
    case 'error':
      return [`- AI explanation failed: ${escapeMarkdown(fix.message)}`]
    case 'done':
      return adviceLines(fix.advice)
  }
}

/** The upgrade commands the backend built from Trivy's fixed versions, or why there are none. */
function noCommandLines(group: PackageGroup): string[] {
  if (group.fix_commands.length > 0) return []
  return [`- Fix commands: ${escapeMarkdown(group.fix_commands_note ?? 'none in the report')}`]
}

/** The built commands as code blocks, after the bullet list (a block would split the list). */
function builtCommandLines(group: PackageGroup): string[] {
  if (group.fix_commands.length === 0) return []
  return [
    '',
    "Fix commands, built by code from Trivy's fixed versions (this app never runs them):",
    '',
    ...group.fix_commands.flatMap((command) => [
      ...(command.label === null ? [] : [escapeMarkdown(command.label), '']),
      codeBlock(command.lines),
      '',
    ]),
    ...(group.fix_commands_note === null ? [] : [escapeMarkdown(group.fix_commands_note), '']),
  ]
}

function groupSection(
  row: Extract<Row, { kind: 'vulnerability' }>,
  index: number,
  fix: FixState | undefined,
  threatLoaded: boolean,
): string[] {
  const { group, findings } = row.shown
  const count =
    findings.length === group.finding_count
      ? String(group.finding_count)
      : `${findings.length} of ${group.finding_count}`
  return [
    `## ${index + 1}. ${escapeMarkdown(group.pkg_name ?? 'unknown package')}`,
    '',
    `- Kind: ${kindLabel('vulnerability')}`,
    `- Installed version: ${codeSpan(group.installed_version ?? 'unknown')}`,
    `- Target: ${escapeMarkdown(group.target)}`,
    `- Findings: ${count} (highest severity: ${severityLabel(row.severity)})`,
    `- Fixed versions: ${trivyFixText(group)}`,
    ...threatLines(group, threatLoaded),
    ...noCommandLines(group),
    ...aiLines(fix),
    ...builtCommandLines(group),
    ...aiCommandLines(fix),
    '',
  ]
}

/** The AI advice for a misconfiguration, a secret or a license. */
function otherAdviceLines(advice: OtherAdvice): string[] {
  const lines = [`- AI answer: ${otherAnswerState(advice.status)}`, `- Summary: ${escapeMarkdown(advice.summary)}`]
  if (advice.solutions.length > 0) {
    lines.push('- Solutions:', ...advice.solutions.map((text, index) => `  ${index + 1}. ${escapeMarkdown(text)}`))
  }
  if (advice.mitigations.length > 0) {
    lines.push('- Mitigations until it is fixed:', ...advice.mitigations.map((text) => `  - ${escapeMarkdown(text)}`))
  }
  lines.push(`- Risks: ${escapeMarkdown(advice.risk_notes)}`)
  return lines
}

function otherAiLines(fix: OtherFixState | undefined): string[] {
  if (fix === undefined) return ['- AI explanation: not requested yet']
  switch (fix.state) {
    case 'queued':
    case 'loading':
      return ['- AI explanation: still running when this summary was made']
    case 'error':
      return [`- AI explanation failed: ${escapeMarkdown(fix.message)}`]
    case 'done':
      return otherAdviceLines(fix.advice)
  }
}

/** "pkg, target"; just the one when the file is also the target. */
function foundIn(place: string, target: string): string {
  return place === target ? place : `${place}, ${target}`
}

function whereText(target: string, start: number | null, end: number | null): string {
  const lines = lineText(start, end)
  return escapeMarkdown(lines === null ? target : `${target}, ${lines}`)
}

function otherSection(row: OtherRow, index: number, result: AnalyzeResult, fix: OtherFixState | undefined): string[] {
  const head = (name: string) => [`## ${index + 1}. ${escapeMarkdown(name)}`, '', `- Kind: ${kindLabel(row.kind)}`]
  const severity = `- Severity: ${severityLabel(row.severity)}`
  switch (row.kind) {
    case 'misconfiguration': {
      const { item } = row
      const noFix = result.report.not_in_format.includes('resolution') ? NOT_IN_FORMAT : 'none in the report'
      return [
        ...head(misconfigurationName(item)),
        severity,
        `- Where: ${whereText(item.target, item.start_line, item.end_line)}`,
        `- What is wrong: ${escapeMarkdown(item.description ?? 'the report gives no description')}`,
        `- Trivy's fix: ${item.resolution === null ? noFix : escapeMarkdown(item.resolution)}`,
        ...otherAiLines(fix),
        '',
      ]
    }
    case 'secret': {
      const { item } = row
      return [
        ...head(secretName(item)),
        severity,
        `- Where: ${whereText(item.target, item.start_line, item.end_line)}`,
        '- How to fix it:',
        ...result.secret_fix_steps.map((step, number) => `  ${number + 1}. ${escapeMarkdown(step)}`),
        "- The secret's value is never part of this file.",
        ...otherAiLines(fix),
        '',
      ]
    }
    case 'license': {
      const { item } = row
      return [
        ...head(item.name ?? 'unknown license'),
        severity,
        `- Category: ${escapeMarkdown(item.category ?? 'unknown')}`,
        `- Found in: ${escapeMarkdown(foundIn(item.pkg_name ?? item.file_path ?? 'unknown', item.target))}`,
        '- Ask your legal or compliance team what this license means for you; this summary lists it and does not judge it.',
        ...otherAiLines(fix),
        '',
      ]
    }
  }
}

function rowSection(row: Row, index: number, input: SummaryInput): string[] {
  if (row.kind === 'vulnerability') {
    const data = input.result.threat_data
    const loaded = data !== undefined && (data.kev.status === 'loaded' || data.epss.status === 'loaded')
    return groupSection(row, index, input.fixFor(row.shown.group), loaded)
  }
  return otherSection(row, index, input.result, input.otherFixFor(row))
}

/** The whole summary: header, then one section per finding the filters show, worst first. */
export function buildFixSummary(input: SummaryInput): string {
  const { report } = input.result
  const missing = missingFieldsText(report)
  const scanDate = fieldOrNotInFormat(report, 'created_at',
    formatScanDate(report.created_at, input.locale, input.timeZone))
  const lines = [
    `# Fix summary: ${escapeMarkdown(fieldOrNotInFormat(report, 'artifact_name', report.artifact_name ?? 'unknown artifact'))}`,
    '',
    `- Report file: ${codeSpan(report.file_name)}. Scan date: ${escapeMarkdown(scanDate)}. ` +
      `Trivy version: ${escapeMarkdown(fieldOrNotInFormat(report, 'trivy_version', report.trivy_version ?? 'unknown'))}.`,
    `- Report format: ${escapeMarkdown(report.report_format)}`,
    ...(missing === null ? [] : [`- Not in this format: ${escapeMarkdown(missing)}`]),
    scannedLine(input.result),
    countsLine(input.result),
    filtersLine(input),
    orderLine(input),
    `- KEV/EPSS data: ${escapeMarkdown(threatStatusText(input.result.threat_data).text)}`,
    `- AI model used: ${input.model === null ? 'none connected yet' : codeSpan(input.model)}`,
    '',
    "> AI suggestions: verify before applying. Only Trivy's fixed versions are ever shown as a fix, " +
      'and the commands were never run.',
    '',
    ...input.rows.flatMap((row, index) => rowSection(row, index, input)),
  ]
  return lines.join('\n')
}
