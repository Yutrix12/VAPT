import { describe, expect, it } from 'vitest'
import { fixCacheKey, isFixAdvice, isLlmTestResult, isThisComputer, toFixGroup } from './llmLogic'
import type { Finding, PackageGroup, ReportDetails } from './types'

function finding(id: string | null, fixed: string | null): Finding {
  return {
    fingerprint: 'f', target: 'python:3.9-slim (debian 13.1)', vuln_class: 'os-pkgs',
    vuln_type: 'debian', vuln_id: id, pkg_name: 'openssl', installed_version: '3.5.1',
    fixed_version: fixed, status: 'fixed', severity: 'HIGH', title: 'a bug',
    cvss_score: 7.5, primary_url: 'https://example.invalid', published_date: null,
  }
}

const group: PackageGroup = {
  target: 'python:3.9-slim (debian 13.1)', pkg_name: 'openssl', installed_version: '3.5.1',
  finding_count: 3, worst_severity: 'HIGH', fixed_versions: ['3.5.4'], has_unfixed: true,
  findings: [finding('CVE-1', '3.5.4'), finding('CVE-2', null), finding(null, null)],
}

const image = { os_family: 'debian', os_name: '13.1', artifact_type: 'container_image' } as ReportDetails
const repo = { os_family: null, os_name: null, artifact_type: 'repository' } as ReportDetails

describe('toFixGroup', () => {
  it('sends only what /api/fix needs for this group', () => {
    expect(toFixGroup(group, image)).toEqual({
      target: 'python:3.9-slim (debian 13.1)', pkg_name: 'openssl', installed_version: '3.5.1',
      ecosystem: 'debian', os: 'debian 13.1', fixed_versions: ['3.5.4'],
      cves: [
        { vuln_id: 'CVE-1', severity: 'HIGH', title: 'a bug', fixed_version: '3.5.4' },
        { vuln_id: 'CVE-2', severity: 'HIGH', title: 'a bug', fixed_version: null },
      ],
    })
  })

  it('has no OS for a repository scan', () => {
    expect(toFixGroup(group, repo).os).toBeNull()
  })
})

describe('isThisComputer', () => {
  it('knows the local addresses', () => {
    for (const url of ['http://localhost:11434', 'http://127.0.0.1:11434', 'http://[::1]:11434']) {
      expect(isThisComputer(url)).toBe(true)
    }
  })

  it('treats everything else as leaving this machine', () => {
    for (const url of ['https://ollama.com', 'http://192.168.1.20:11434', 'http://localhost.evil.example', 'nonsense']) {
      expect(isThisComputer(url)).toBe(false)
    }
  })
})

describe('fixCacheKey', () => {
  it('differs per group and per model, and ignores surrounding spaces', () => {
    const key = fixCacheKey(group, { baseUrl: 'http://localhost:11434', model: 'llama3.2', apiKey: '' })
    expect(fixCacheKey(group, { baseUrl: 'http://localhost:11434/ ', model: ' llama3.2', apiKey: 'x' })).toBe(key)
    expect(fixCacheKey(group, { baseUrl: 'http://localhost:11434', model: 'qwen3:8b', apiKey: '' })).not.toBe(key)
  })
})

describe('answer shape checks', () => {
  it('recognises the backend answers', () => {
    expect(isLlmTestResult({ ok: true, models: ['a'], model_found: true })).toBe(true)
    expect(isLlmTestResult({ ok: true })).toBe(false)
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
