// Plain functions behind the AI explanations (no React).
import {
  type FixGroupRequest,
  type FixStatus,
  type License,
  type LicenseRequest,
  type Misconfiguration,
  type MisconfigurationRequest,
  type OtherAdvice,
  type PackageGroup,
  type ReportDetails,
  type Secret,
  type SecretRequest,
} from '../../api/types'
import { countText } from '../../shared/text'

/** The body of /api/fix: this group only, nothing else from the report. */
export function toFixGroup(group: PackageGroup, report: ReportDetails): FixGroupRequest {
  const os = [report.os_family, report.os_name].filter(Boolean).join(' ')
  return {
    target: group.target,
    pkg_name: group.pkg_name,
    installed_version: group.installed_version,
    ecosystem: group.findings[0]?.vuln_type ?? null,
    os: os || null,
    fixed_versions: group.fixed_versions,
    cves: group.findings.flatMap((f) =>
      // A finding without an ID cannot be explained, so it is left out.
      f.vuln_id === null
        ? []
        : [{ vuln_id: f.vuln_id, severity: f.severity, title: f.title, fixed_version: f.fixed_version }],
    ),
  }
}

/**
 * Runs the added tasks one after another, never two at once, so a local
 * model is never asked several things at the same time.
 */
export function serialQueue(): (task: () => Promise<void>) => Promise<void> {
  let last = Promise.resolve()
  return (task) => {
    const run = last.then(task)
    // A failed task must not stop the ones after it; its caller still
    // gets the failure through `run`.
    last = run.catch(() => undefined)
    return run
  }
}

/** The sentence for vulnerabilities that no upgrade closes (page and fix summary). */
export function openAfterUpgradeText(count: number): string {
  const one = count === 1
  return (
    `${countText(count, 'vulnerability', 'vulnerabilities')} in this package ${one ? 'has' : 'have'} ` +
    `no fixed version yet and ${one ? 'stays' : 'stay'} open after any upgrade.`
  )
}

/**
 * The state of an AI answer in plain words (a failed request is the "error"
 * state of the panel, not an answer). Which version is a fix is decided by code.
 */
export function answerState(status: FixStatus): string {
  switch (status) {
    case 'verified':
      return 'Verified fix'
    case 'unverified':
    case 'no_version_suggested':
      return 'Solution options'
    case 'no_fix_available':
      return 'No fix yet: mitigations'
  }
}

/** The body of /api/fix/other for a misconfiguration: what is wrong and Trivy's fix text, no message or code. */
export function misconfigurationRequest(item: Misconfiguration): MisconfigurationRequest {
  return {
    kind: 'misconfiguration',
    check_id: item.check_id,
    title: item.title,
    description: item.description,
    resolution: item.resolution,
    severity: item.severity,
    misconf_type: item.misconf_type,
    target: item.target,
    start_line: item.start_line,
    end_line: item.end_line,
  }
}

/** The body of /api/fix/other for a secret: the rule and the place, never a value (the page has none). */
export function secretRequest(item: Secret): SecretRequest {
  return {
    kind: 'secret',
    rule_id: item.rule_id,
    category: item.category,
    severity: item.severity,
    title: item.title,
    target: item.target,
    start_line: item.start_line,
    end_line: item.end_line,
  }
}

/** The body of /api/fix/other for a license: its name and category, and where it was found. */
export function licenseRequest(item: License): LicenseRequest {
  return {
    kind: 'license',
    name: item.name,
    category: item.category,
    license_class: item.license_class,
    package: item.pkg_name ?? item.file_path,
    severity: item.severity,
  }
}

/** The state of the AI advice for a misconfiguration, a secret or a license, in plain words. */
export function otherAnswerState(status: OtherAdvice['status']): string {
  return status === 'solution_options' ? 'Solution options' : 'Mitigations only'
}
