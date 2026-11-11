import { describe, expect, it } from 'vitest'
import { isFixAdvice, isLlmStatus } from './api/guards'
import type { Finding, PackageGroup, ReportDetails } from './api/types'
import { connectionFromStatus } from './features/ai-status/connection'
import { serialQueue, toFixGroup } from './features/fixes/fixLogic'

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

describe('serialQueue', () => {
  it('runs one task at a time, in the order they were added', async () => {
    const add = serialQueue()
    const log: string[] = []
    let running = 0
    const task = (name: string, ms: number) => async () => {
      running += 1
      log.push(`start ${name} (${running} running)`)
      await new Promise((resolve) => setTimeout(resolve, ms))
      log.push(`end ${name}`)
      running -= 1
    }
    await Promise.all([add(task('a', 20)), add(task('b', 1)), add(task('c', 1))])
    expect(log).toEqual([
      'start a (1 running)', 'end a', 'start b (1 running)', 'end b', 'start c (1 running)', 'end c',
    ])
  })

  it('keeps going after a failed task, and its caller still sees the failure', async () => {
    const add = serialQueue()
    const failed = add(async () => {
      throw new Error('boom')
    })
    let ranAfter = false
    const next = add(async () => {
      ranAfter = true
    })
    await expect(failed).rejects.toThrow('boom')
    await next
    expect(ranAfter).toBe(true)
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
