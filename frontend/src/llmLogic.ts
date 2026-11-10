// Plain functions behind the AI status and the AI explanations (no React).
import type { ApiResult } from './api'
import { isObject } from './reportLogic'
import {
  FIX_STATUSES,
  type AiConnection,
  type FixAdvice,
  type FixGroupRequest,
  type LlmStatus,
  type PackageGroup,
  type ReportDetails,
} from './types'

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

/** The result of a connection check, as the page shows it. */
export function connectionFromStatus(result: ApiResult<LlmStatus>): AiConnection {
  if (!result.ok) return { state: 'error', message: result.message }
  const { model, model_found, leaves_this_computer } = result.data
  if (model_found) return { state: 'ready', model, leavesThisComputer: leaves_this_computer }
  return {
    state: 'error',
    message: leaves_this_computer
      ? `The hosted AI service does not offer the model ${model}.`
      : `Ollama answers, but it does not have the model ${model}. Install it with: ollama pull ${model}`,
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

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

export function isLlmStatus(body: unknown): body is LlmStatus {
  return (
    isObject(body) &&
    typeof body.model === 'string' &&
    typeof body.model_found === 'boolean' &&
    typeof body.leaves_this_computer === 'boolean'
  )
}

export function isFixAdvice(body: unknown): body is FixAdvice {
  if (
    !isObject(body) ||
    typeof body.status !== 'string' ||
    !(FIX_STATUSES as readonly string[]).includes(body.status) ||
    !isStringArray(body.commands) ||
    !isStringArray(body.trivy_fixed_versions) ||
    typeof body.mitigation_only !== 'boolean' ||
    typeof body.cves_without_fix !== 'number' ||
    ![body.summary, body.recommended_action, body.risk_notes, body.disclaimer].every(
      (text) => typeof text === 'string',
    )
  ) {
    return false
  }
  // The verdict needs the version its status talks about.
  if (body.status === 'verified') return typeof body.target_version === 'string'
  if (body.status === 'unverified') return typeof body.unverified_version === 'string'
  return true
}
