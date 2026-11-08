// Calls to our backend. The Vite dev proxy forwards /api/ to FastAPI.
import { isFixAdvice, isLlmTestResult, toSettingsBody } from './llmLogic'
import { isAnalyzeResult, isObject } from './reportLogic'
import type { AnalyzeResult, FixAdvice, FixGroupRequest, LlmSettings, LlmTestResult } from './types'

export type Health =
  | { state: 'checking' }
  | { state: 'ok' }
  | { state: 'error'; message: string }

export type ApiResult<T> = { ok: true; data: T } | { ok: false; message: string }

const HEALTH_TIMEOUT_MS = 5000
const ANALYZE_TIMEOUT_MS = 60000
// A little longer than the backend's own limits (10 s and 120 s), so its
// clearer message arrives first.
const LLM_TEST_TIMEOUT_MS = 20000
const FIX_TIMEOUT_MS = 150000
const NOT_RUNNING = 'Cannot reach the backend. Start it as described in README.md.'

function isTimeout(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'TimeoutError'
}

/**
 * Call our backend; every problem becomes one readable message. The answer
 * is checked with `isExpected` and returned unchanged: hidden characters
 * are made visible only where text is shown (visibleText).
 */
async function callBackend<T>(
  path: string,
  init: RequestInit,
  timeoutMs: number,
  isExpected: (body: unknown) => body is T,
): Promise<ApiResult<T>> {
  let response: Response
  let body: unknown
  try {
    response = await fetch(path, { ...init, signal: AbortSignal.timeout(timeoutMs) })
    // The timeout also covers reading the answer; invalid JSON becomes null.
    body = await response.json().catch((error: unknown) => {
      if (isTimeout(error)) throw error
      return null
    })
  } catch (error) {
    // No (complete) answer arrived: timeout or no connection.
    return isTimeout(error)
      ? { ok: false, message: `The backend did not answer within ${timeoutMs / 1000} seconds.` }
      : { ok: false, message: NOT_RUNNING }
  }
  if (response.ok) {
    return isExpected(body)
      ? { ok: true, data: body }
      : { ok: false, message: 'The backend sent an unexpected answer.' }
  }
  // Our backend always sends {"detail": "one line"}; the Vite proxy answers
  // 502-504 without a body when the backend is not running.
  if (isObject(body) && typeof body.detail === 'string') {
    return { ok: false, message: body.detail }
  }
  if (response.status >= 502 && response.status <= 504) return { ok: false, message: NOT_RUNNING }
  return { ok: false, message: `The backend answered with HTTP ${response.status}.` }
}

function isHealthy(body: unknown): body is { status: 'ok' } {
  return isObject(body) && body.status === 'ok'
}

/** Ask the backend if it is running. Never rejects. */
export async function checkHealth(): Promise<Health> {
  const result = await callBackend('/api/health', {}, HEALTH_TIMEOUT_MS, isHealthy)
  return result.ok ? { state: 'ok' } : { state: 'error', message: result.message }
}

/** Upload one report to /api/analyze. Never rejects. */
export function analyzeReport(file: File): Promise<ApiResult<AnalyzeResult>> {
  const form = new FormData()
  form.append('file', file)
  return callBackend('/api/analyze', { method: 'POST', body: form }, ANALYZE_TIMEOUT_MS, isAnalyzeResult)
}

function jsonPost(body: unknown): RequestInit {
  return { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

/** "Check connection": does Ollama answer, and does it have the model? Never rejects. */
export function testLlm(settings: LlmSettings): Promise<ApiResult<LlmTestResult>> {
  return callBackend('/api/llm/test', jsonPost(toSettingsBody(settings)), LLM_TEST_TIMEOUT_MS, isLlmTestResult)
}

/** The AI explanation for one group; the API key travels only in this request body. */
export function explainFix(settings: LlmSettings, group: FixGroupRequest): Promise<ApiResult<FixAdvice>> {
  const body = { settings: toSettingsBody(settings), group }
  return callBackend('/api/fix', jsonPost(body), FIX_TIMEOUT_MS, isFixAdvice)
}
