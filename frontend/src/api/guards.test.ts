import { describe, expect, it } from 'vitest'
import { isAnalyzeResult, isFixAdvice, isLlmStatus } from './guards'

describe('isAnalyzeResult', () => {
  it('accepts the shape /api/analyze returns', () => {
    expect(isAnalyzeResult({
      report: {}, summary: { by_severity: {}, by_status: {} }, package_groups: [],
    })).toBe(true)
  })

  it('refuses other answers', () => {
    expect(isAnalyzeResult({})).toBe(false)
    expect(isAnalyzeResult([])).toBe(false)
    expect(isAnalyzeResult({ report: {}, summary: {}, package_groups: [] })).toBe(false)
  })
})

describe('answer shape checks', () => {
  it('recognises the backend answers', () => {
    expect(isLlmStatus({ model: 'qwen3:8b', model_found: true, leaves_this_computer: false })).toBe(true)
    expect(isLlmStatus({ model: 'qwen3:8b', model_found: true })).toBe(false)
    expect(isFixAdvice({
      status: 'verified', target_version: '1', unverified_version: null, trivy_fixed_versions: ['1'],
      mitigation_only: false, cves_without_fix: 0, summary: 's', recommended_action: 'a',
      commands: [], risk_notes: 'r', disclaimer: 'd',
    })).toBe(true)
    expect(isFixAdvice({ status: 'made-up', commands: [] })).toBe(false)
  })

  it('needs the version that its status promises', () => {
    const base = {
      target_version: null, unverified_version: null, trivy_fixed_versions: ['1'],
      mitigation_only: false, cves_without_fix: 0, summary: 's', recommended_action: 'a',
      commands: [], risk_notes: 'r', disclaimer: 'd',
    }
    expect(isFixAdvice({ ...base, status: 'verified' })).toBe(false) // no target_version
    expect(isFixAdvice({ ...base, status: 'unverified' })).toBe(false) // no unverified_version
    expect(isFixAdvice({ ...base, status: 'unverified', unverified_version: '9.9.9' })).toBe(true)
    expect(isFixAdvice({ ...base, status: 'no_fix_available', mitigation_only: 'yes' })).toBe(false)
  })
})
