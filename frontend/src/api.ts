// Calls to our backend. The Vite dev proxy forwards /api/ to FastAPI.

export type Health =
  | { state: 'checking' }
  | { state: 'ok' }
  | { state: 'error'; message: string }

const TIMEOUT_MS = 5000
const NOT_RUNNING = 'Cannot reach the backend. Start it as described in README.md.'

/** Ask the backend if it is running. Never rejects: problems become an error state. */
export async function checkHealth(): Promise<Health> {
  let response: Response
  try {
    response = await fetch('/api/health', { signal: AbortSignal.timeout(TIMEOUT_MS) })
  } catch (error) {
    // fetch rejects only when no answer arrived: timeout or no connection.
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      return { state: 'error', message: `The backend did not answer within ${TIMEOUT_MS / 1000} seconds.` }
    }
    return { state: 'error', message: NOT_RUNNING }
  }
  // The Vite proxy answers 502-504 itself when the backend is not running.
  if (response.status >= 502 && response.status <= 504) {
    return { state: 'error', message: NOT_RUNNING }
  }
  if (!response.ok) {
    return { state: 'error', message: `The backend answered with HTTP ${response.status}.` }
  }
  const body: unknown = await response.json().catch(() => null)
  if (typeof body === 'object' && body !== null && 'status' in body && body.status === 'ok') {
    return { state: 'ok' }
  }
  return { state: 'error', message: 'The backend sent an unexpected answer.' }
}
