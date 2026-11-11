import { describe, expect, it } from 'vitest'
import { connectionFromStatus } from './connection'

describe('connectionFromStatus', () => {
  const local = { model: 'qwen3:8b', model_found: true, leaves_this_computer: false }

  it('is ready when the backend LLM answers and has its model', () => {
    expect(connectionFromStatus({ ok: true, data: local })).toEqual(
      { state: 'ready', model: 'qwen3:8b', leavesThisComputer: false })
    expect(connectionFromStatus({ ok: true, data: { ...local, leaves_this_computer: true } })).toEqual(
      { state: 'ready', model: 'qwen3:8b', leavesThisComputer: true })
  })

  it('says how to install a missing local model', () => {
    const connection = connectionFromStatus({ ok: true, data: { ...local, model_found: false } })
    expect(connection.state === 'error' && connection.message).toContain('ollama pull qwen3:8b')
  })

  it('does not suggest installing when the model is missing at a hosted API', () => {
    const connection = connectionFromStatus({
      ok: true, data: { ...local, model_found: false, leaves_this_computer: true },
    })
    expect(connection.state === 'error' && connection.message).not.toContain('ollama pull')
  })

  it('passes on the error of a failed check', () => {
    expect(connectionFromStatus({ ok: false, message: 'Cannot reach Ollama.' }))
      .toEqual({ state: 'error', message: 'Cannot reach Ollama.' })
  })
})
