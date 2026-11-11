// The "fix summary" Markdown file, built from what the page shows (no React).
//
// Report text and AI text are untrusted, and the file is opened in other
// programs (VS Code, GitHub, wikis). Every such text goes through
// escapeMarkdown, codeSpan or codeBlock, so it can never become a link,
// HTML, a heading or formatting, and hidden characters show as codes.
import {
  ALL_STATUSES,
  artifactTypeLabel,
  countText,
  formatScanDate,
  KEEP_LINE_BREAKS,
  openAfterUpgradeText,
  RATED_SEVERITIES,
  severityLabel,
  visibleText,
  type ShownGroup,
} from './reportLogic'
import { SEVERITIES, type AnalyzeResult, type FixAdvice, type FixState, type PackageGroup, type Severity } from './types'

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
  shown: ShownGroup[] // the groups and findings the filters show
  severities: ReadonlySet<Severity>
  status: string // ALL_STATUSES or one status value
  fixFor: (group: PackageGroup) => FixState | undefined
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
    `- Artifact type: ${escapeMarkdown(artifactTypeLabel(report.artifact_type))}; ` +
    `operating system: ${escapeMarkdown(os || 'unknown')}`
  )
}

function countsLine(result: AnalyzeResult): string {
  const { summary } = result
  const rated = RATED_SEVERITIES.map((s) => `${summary.by_severity[s]} ${severityLabel(s)}`).join(', ')
  return (
    `- ${countText(summary.total, 'finding')} in ${countText(summary.unique_packages, 'package')}: ` +
    `${rated}; ${summary.by_severity.UNKNOWN} Unknown (not rated)`
  )
}

function filtersLine(input: SummaryInput): string {
  const filters: string[] = []
  if (input.severities.size < SEVERITIES.length) {
    const on = SEVERITIES.filter((s) => input.severities.has(s)).map(severityLabel)
    filters.push(on.length > 0 ? `severity ${on.join(', ')}` : 'no severity')
  }
  if (input.status !== ALL_STATUSES) filters.push(`status ${codeSpan(input.status)}`)
  const total = input.result.package_groups.length
  let listed = `${input.shown.length} of ${countText(total, 'package')}`
  if (total === 0) listed = 'no packages'
  else if (input.shown.length === total) listed = total === 1 ? '1 package' : `all ${countText(total, 'package')}`
  return `- Filters: ${filters.length > 0 ? filters.join('; ') : 'none'}. This summary lists ${listed}.`
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
  lines.push(
    `- Summary: ${escapeMarkdown(advice.summary)}`,
    `- ${advice.mitigation_only ? 'Mitigation' : 'What to do'}: ${escapeMarkdown(advice.recommended_action)}`,
    `- Risks: ${escapeMarkdown(advice.risk_notes)}`,
  )
  if (advice.commands.length > 0) {
    lines.push(
      '',
      'AI-suggested commands (verify before running; never run by this app):',
      '',
      codeBlock(advice.commands),
    )
  }
  return lines
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

function groupSection(item: ShownGroup, index: number, fix: FixState | undefined): string[] {
  const { group, findings, worst } = item
  const count =
    findings.length === group.finding_count
      ? String(group.finding_count)
      : `${findings.length} of ${group.finding_count}`
  return [
    `## ${index + 1}. ${escapeMarkdown(group.pkg_name ?? 'unknown package')}`,
    '',
    `- Installed version: ${codeSpan(group.installed_version ?? 'unknown')}`,
    `- Target: ${escapeMarkdown(group.target)}`,
    `- Findings: ${count} (highest severity: ${severityLabel(worst)})`,
    `- Fixed versions: ${trivyFixText(group)}`,
    ...aiLines(fix),
    '',
  ]
}

/** The whole summary: header, then one section per shown package, worst first. */
export function buildFixSummary(input: SummaryInput): string {
  const { report } = input.result
  const scanDate = formatScanDate(report.created_at, input.locale, input.timeZone)
  const lines = [
    `# Fix summary: ${escapeMarkdown(report.artifact_name ?? 'unknown artifact')}`,
    '',
    `- Report file: ${codeSpan(report.file_name)}. Scan date: ${escapeMarkdown(scanDate)}. ` +
      `Trivy version: ${escapeMarkdown(report.trivy_version ?? 'unknown')}.`,
    scannedLine(input.result),
    countsLine(input.result),
    filtersLine(input),
    `- AI model used: ${input.model === null ? 'none connected yet' : codeSpan(input.model)}`,
    '',
    "> AI suggestions: verify before applying. Only Trivy's fixed versions are ever shown as a fix, " +
      'and the commands were never run.',
    '',
    ...input.shown.flatMap((item, index) => groupSection(item, index, input.fixFor(item.group))),
  ]
  return lines.join('\n')
}
