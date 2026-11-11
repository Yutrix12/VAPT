import { describe, expect, it } from 'vitest'
import type { Finding, License, Misconfiguration, PackageGroup, ReportDetails, Secret } from '../../api/types'
import {
  answerState,
  licenseRequest,
  misconfigurationRequest,
  openAfterUpgradeText,
  otherAnswerState,
  secretRequest,
  serialQueue,
  toFixGroup,
} from './fixLogic'

describe('openAfterUpgradeText', () => {
  it('says how many vulnerabilities stay open, in singular or plural', () => {
    expect(openAfterUpgradeText(1)).toBe(
      '1 vulnerability in this package has no fixed version yet and stays open after any upgrade.')
    expect(openAfterUpgradeText(3)).toBe(
      '3 vulnerabilities in this package have no fixed version yet and stay open after any upgrade.')
  })
})

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
  fix_commands: [], fix_commands_note: null,
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

describe('answerState', () => {
  it('names the state of an AI answer in plain words', () => {
    expect(answerState('verified')).toBe('Verified fix')
    expect(answerState('unverified')).toBe('Solution options')
    expect(answerState('no_version_suggested')).toBe('Solution options')
    expect(answerState('no_fix_available')).toBe('No fix yet: mitigations')
  })
})

describe('requests for the other kinds', () => {
  const secret: Secret = {
    fingerprint: 'fp', target: 'deploy.sh', rule_id: 'aws-access-key-id', category: 'AWS', severity: 'CRITICAL',
    title: 'AWS Access Key ID', start_line: 3, end_line: 3,
  }
  const misconfiguration: Misconfiguration = {
    fingerprint: 'fp', target: 'Dockerfile', misconf_type: 'dockerfile', check_type: 'x', check_id: 'DS-0002',
    title: 'Image user should not be root', description: 'Root is risky.', resolution: 'Add a USER line.',
    severity: 'HIGH', status: 'FAIL', primary_url: 'https://example.invalid', references: ['r'], resource: 'res',
    start_line: null, end_line: null,
  }
  const license: License = {
    fingerprint: 'fp', target: 'Java', license_class: 'license', pkg_name: 'org.a:a', file_path: null,
    name: 'EPL-1.0', category: 'reciprocal', severity: 'MEDIUM', confidence: 0.9, link: 'https://example.invalid',
  }

  it('a secret request holds the rule, place and severity and nothing else', () => {
    expect(Object.keys(secretRequest(secret)).sort()).toEqual(
      ['category', 'end_line', 'kind', 'rule_id', 'severity', 'start_line', 'target', 'title'])
    expect(secretRequest(secret)).toMatchObject({ kind: 'secret', rule_id: 'aws-access-key-id', start_line: 3 })
  })

  it('a misconfiguration request holds what is wrong and Trivy fix text, never a message or code', () => {
    expect(Object.keys(misconfigurationRequest(misconfiguration)).sort()).toEqual(
      ['check_id', 'description', 'end_line', 'kind', 'misconf_type', 'resolution', 'severity', 'start_line',
        'target', 'title'])
  })

  it('cuts long texts to the limits of the backend, so a long description never makes the request fail', () => {
    const long = 'x'.repeat(20_000)
    const request = misconfigurationRequest({ ...misconfiguration, title: long, description: long, resolution: long, target: long })
    expect(request.title?.length).toBe(1000)
    expect(request.description?.length).toBe(5000)
    expect(request.resolution?.length).toBe(5000)
    expect(request.target.length).toBe(2000)
    expect(secretRequest({ ...secret, title: long, target: long }).title?.length).toBe(1000)
    expect(licenseRequest({ ...license, name: long }).name?.length).toBe(500)
    expect(misconfigurationRequest(misconfiguration).description).toBe('Root is risky.') // short texts stay
  })

  it('a license request names the package, or the file when there is no package', () => {
    expect(licenseRequest(license)).toEqual({
      kind: 'license', name: 'EPL-1.0', category: 'reciprocal', license_class: 'license', package: 'org.a:a',
      severity: 'MEDIUM',
    })
    expect(licenseRequest({ ...license, pkg_name: null, file_path: 'LICENSE.txt' }).package).toBe('LICENSE.txt')
  })
})

describe('otherAnswerState', () => {
  it('names the state of the advice for a misconfiguration, a secret or a license', () => {
    expect(otherAnswerState('solution_options')).toBe('Solution options')
    expect(otherAnswerState('mitigations_only')).toBe('Mitigations only')
  })
})
