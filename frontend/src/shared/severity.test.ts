import { describe, expect, it } from 'vitest'
import type { Severity } from '../api/types'
import { RATED_SEVERITIES, severityLabel, severityLevel, worstSeverity } from './severity'

describe('severity levels', () => {
  it('gives a higher number to a more severe level', () => {
    expect(RATED_SEVERITIES.map(severityLevel)).toEqual([4, 3, 2, 1])
  })

  it('gives UNKNOWN no level: it is not part of the ranking', () => {
    expect(severityLevel('UNKNOWN')).toBeNull()
    expect(RATED_SEVERITIES).not.toContain('UNKNOWN')
  })

  it('takes the most severe rated level, and UNKNOWN only when nothing is rated', () => {
    expect(worstSeverity(['LOW', 'UNKNOWN', 'HIGH'])).toBe('HIGH')
    expect(worstSeverity(['UNKNOWN', 'LOW'])).toBe('LOW')
    expect(worstSeverity(['UNKNOWN'])).toBe('UNKNOWN')
  })
})

describe('severityLabel', () => {
  it('writes each severity in sentence case', () => {
    expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((s) => severityLabel(s as Severity)))
      .toEqual(['Critical', 'High', 'Medium', 'Low', 'Unknown'])
  })
})
