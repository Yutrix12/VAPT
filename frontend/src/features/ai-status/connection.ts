// The AI connection state the page shows.
import type { ApiResult } from '../../api/client'
import { type AiConnection, type LlmStatus } from '../../api/types'

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
