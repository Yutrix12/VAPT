// Light checks that an answer from the backend has the shape the page expects.
import { type AnalyzeResult, FIX_STATUSES, type FixAdvice, type LlmStatus } from './types'

/** True for a plain JSON object (not null, not an array). */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** A light check that an answer has the shape of /api/analyze's response. */
export function isAnalyzeResult(body: unknown): body is AnalyzeResult {
  return (
    isObject(body) &&
    isObject(body.report) &&
    isObject(body.summary) &&
    isObject(body.summary.by_severity) &&
    isObject(body.summary.by_status) &&
    Array.isArray(body.package_groups)
  )
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
