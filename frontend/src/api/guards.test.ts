import { describe, expect, it } from 'vitest'
import { isAnalyzeResult, isFixAdvice, isLlmStatus } from './guards'

/** The shape /api/analyze returns, with every kind empty. */
const answer = {
  report: {},
  summary: { by_severity: {}, by_status: {}, by_kind: { vulnerability: 0, misconfiguration: 0, secret: 0, license: 0 } },
  package_groups: [],
  misconfigurations: [],
  secrets: [],
  licenses: [],
  secret_fix_steps: ['Revoke the secret.'],
}

describe('isAnalyzeResult', () => {
  it('accepts the shape /api/analyze returns', () => {
    expect(isAnalyzeResult(answer)).toBe(true)
  })

  it('refuses other answers', () => {
    expect(isAnalyzeResult({})).toBe(false)
    expect(isAnalyzeResult([])).toBe(false)
    expect(isAnalyzeResult({ report: {}, summary: {}, package_groups: [] })).toBe(false)
  })

  it('refuses an answer that lacks a finding kind or its fix steps', () => {
    for (const field of ['misconfigurations', 'secrets', 'licenses', 'secret_fix_steps'] as const) {
      const { [field]: _removed, ...without } = answer
      expect(isAnalyzeResult(without), `without ${field}`).toBe(false)
      expect(isAnalyzeResult({ ...answer, [field]: 'nope' }), `${field} as text`).toBe(false)
    }
    expect(isAnalyzeResult({ ...answer, summary: { by_severity: {}, by_status: {} } })).toBe(false) // no by_kind
    expect(isAnalyzeResult({ ...answer, secret_fix_steps: [1, 2] })).toBe(false)
  })

  it('refuses a by_kind that lacks one of the four kinds or has a non-number', () => {
    const kinds: Record<string, number> = answer.summary.by_kind
    for (const kind of Object.keys(kinds)) {
      const { [kind]: _removed, ...without } = kinds
      expect(isAnalyzeResult({ ...answer, summary: { ...answer.summary, by_kind: without } }), `without ${kind}`).toBe(false)
      expect(isAnalyzeResult({ ...answer, summary: { ...answer.summary, by_kind: { ...kinds, [kind]: '1' } } })).toBe(false)
    }
  })
})

describe('answer shape checks', () => {
  it('recognises the backend answers', () => {
    expect(isLlmStatus({ model: 'qwen3:8b', model_found: true, leaves_this_computer: false })).toBe(true)
    expect(isLlmStatus({ model: 'qwen3:8b', model_found: true })).toBe(false)
    expect(isFixAdvice({
      status: 'verified', target_version: '1', unverified_version: null, trivy_fixed_versions: ['1'],
      mitigation_only: false, cves_without_fix: 0, summary: 's', solutions: ['a'], mitigations: [],
      unsafe_commands_removed: 0, commands: [], risk_notes: 'r', disclaimer: 'd',
    })).toBe(true)
    expect(isFixAdvice({ status: 'made-up', commands: [] })).toBe(false)
  })

  it('refuses an answer whose solutions or mitigations are not lists of text, or that lacks the removed count', () => {
    const good = {
      status: 'no_fix_available', target_version: null, unverified_version: null, trivy_fixed_versions: [],
      mitigation_only: true, cves_without_fix: 1, summary: 's', solutions: [], mitigations: ['m'],
      unsafe_commands_removed: 0, commands: [], risk_notes: 'r', disclaimer: 'd',
    }
    expect(isFixAdvice(good)).toBe(true)
    expect(isFixAdvice({ ...good, solutions: 'one' })).toBe(false)
    expect(isFixAdvice({ ...good, mitigations: [1] })).toBe(false)
    expect(isFixAdvice({ ...good, unsafe_commands_removed: 'x' })).toBe(false)
    const { solutions: _removed, ...without } = good
    expect(isFixAdvice(without)).toBe(false)
  })

  it('needs the version that its status promises', () => {
    const base = {
      target_version: null, unverified_version: null, trivy_fixed_versions: ['1'],
      mitigation_only: false, cves_without_fix: 0, summary: 's', solutions: ['a'], mitigations: [],
      unsafe_commands_removed: 0, commands: [], risk_notes: 'r', disclaimer: 'd',
    }
    expect(isFixAdvice({ ...base, status: 'verified' })).toBe(false) // no target_version
    expect(isFixAdvice({ ...base, status: 'unverified' })).toBe(false) // no unverified_version
    expect(isFixAdvice({ ...base, status: 'unverified', unverified_version: '9.9.9' })).toBe(true)
    expect(isFixAdvice({ ...base, status: 'no_fix_available', mitigation_only: 'yes' })).toBe(false)
  })
})
