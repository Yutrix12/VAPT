// Plain functions behind the AI status and the AI explanations (no React).
import { type FixGroupRequest, type PackageGroup, type ReportDetails } from './api/types'

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
