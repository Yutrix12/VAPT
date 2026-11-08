// Plain functions behind the AI settings and the AI explanations (no React).
import type { ApiResult } from './api'
import { groupKey, isObject } from './reportLogic'
import {
  FIX_STATUSES,
  type AiConnection,
  type FixAdvice,
  type FixGroupRequest,
  type LlmSettings,
  type LlmTestResult,
  type PackageGroup,
  type ReportDetails,
} from './types'

export const DEFAULT_BASE_URL = 'http://localhost:11434'
/** The one model the app uses (owner's decision). */
export const AI_MODEL = 'qwen3:8b'

/** The body "group" for /api/fix: this group only, nothing else from the report. */
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

/** True if the URL points at this computer (localhost or a loopback address). */
export function isThisComputer(url: string): boolean {
  let hostname: string
  try {
    hostname = new URL(url).hostname
  } catch {
    return false // not a valid URL: treat it as not local
  }
  return hostname === 'localhost' || hostname === '[::1]' || /^127(\.\d{1,3}){3}$/.test(hostname)
}

/** One cached AI answer per group and per Ollama address. */
export function fixCacheKey(group: PackageGroup, settings: LlmSettings): string {
  const baseUrl = settings.baseUrl.trim().replace(/\/+$/, '')
  return JSON.stringify([groupKey(group), baseUrl])
}

/** The settings as the backend expects them; the key only when filled. */
export function toSettingsBody(settings: LlmSettings): Record<string, string> {
  const body: Record<string, string> = { base_url: settings.baseUrl.trim(), model: AI_MODEL }
  const key = settings.apiKey.trim()
  if (key) body.api_key = key
  return body
}

/** The result of a connection check, as the page shows it. */
export function connectionFromTest(result: ApiResult<LlmTestResult>): AiConnection {
  if (!result.ok) return { state: 'error', message: result.message }
  if (result.data.model_found) return { state: 'ready' }
  return {
    state: 'error',
    message: `Ollama answers, but it does not have the model ${AI_MODEL}. On this computer, install it with: ollama pull ${AI_MODEL}`,
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

export function isLlmTestResult(body: unknown): body is LlmTestResult {
  return (
    isObject(body) && body.ok === true && isStringArray(body.models) && typeof body.model_found === 'boolean'
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
