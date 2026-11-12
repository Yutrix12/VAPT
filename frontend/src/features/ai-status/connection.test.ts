import { describe, expect, it } from 'vitest'
import { BACKEND_UNREACHABLE } from '../../api/client'
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

  it('does not repeat the backend message when the backend itself is down: it says what that means for the AI', () => {
    const connection = connectionFromStatus({ ok: false, message: BACKEND_UNREACHABLE })
    expect(connection.state).toBe('error')
    const message = connection.state === 'error' ? connection.message : ''
    expect(message).not.toBe(BACKEND_UNREACHABLE)
    expect(message).toContain('AI')
    expect(message).toContain('backend')
  })

  it('passes on the error of a failed check', () => {
    expect(connectionFromStatus({ ok: false, message: 'Cannot reach Ollama.' }))
      .toEqual({ state: 'error', message: 'Cannot reach Ollama.' })
  })
})
