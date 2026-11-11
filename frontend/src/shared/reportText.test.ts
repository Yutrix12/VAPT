import { describe, expect, it } from 'vitest'
import {
  artifactTypeLabel,
  fieldOrNotInFormat,
  kindLabel,
  lineText,
  missingFieldsText,
  overviewText,
  shownText,
} from './reportText'

describe('fieldOrNotInFormat', () => {
  it('says "not in this format" only for the fields the format lacks', () => {
    const lacking = { not_in_format: ['created_at', 'os'] }
    expect(fieldOrNotInFormat(lacking, 'created_at', 'unknown')).toBe('not in this format')
    expect(fieldOrNotInFormat(lacking, 'trivy_version', '0.76.2')).toBe('0.76.2')
    expect(fieldOrNotInFormat({ not_in_format: [] }, 'created_at', 'unknown')).toBe('unknown')
  })
})

describe('artifactTypeLabel', () => {
  it('names every artifact type of Trivy 0.76.2 in plain words', () => {
    expect(['container_image', 'filesystem', 'repository', 'cyclonedx', 'spdx', 'aws_account', 'vm']
      .map(artifactTypeLabel)).toEqual([
      'Container image', 'Filesystem', 'Repository', 'CycloneDX SBOM', 'SPDX SBOM', 'AWS account',
      'Virtual machine image',
    ])
  })

  it('shows any other value as Trivy wrote it, and unknown when missing', () => {
    expect(artifactTypeLabel('something_new')).toBe('something_new')
    expect(artifactTypeLabel(null)).toBe('unknown')
  })
})

describe('missingFieldsText', () => {
  it('lists, in plain words, what the format lacks and is not shown elsewhere', () => {
    const text = { not_in_format: ['created_at', 'os', 'cvss_score', 'published_date', 'full_titles', 'resolution'] }
    expect(missingFieldsText(text)).toBe(
      'CVSS scores, published dates, full vulnerability titles (Trivy shortens them), fix texts for misconfigurations')
  })

  it('is null for a report that lacks nothing of these', () => {
    expect(missingFieldsText({ not_in_format: [] })).toBeNull()
    expect(missingFieldsText({ not_in_format: ['created_at', 'os'] })).toBeNull()
  })
})

describe('kindLabel', () => {
  it('names each finding kind', () => {
    expect(['vulnerability', 'misconfiguration', 'secret', 'license'].map((kind) => kindLabel(kind as never))).toEqual([
      'Vulnerability', 'Misconfiguration', 'Secret', 'License'])
  })
})

describe('lineText', () => {
  it('says the line or the lines, or nothing when the report has none', () => {
    expect(lineText(3, 3)).toBe('line 3')
    expect(lineText(3, null)).toBe('line 3')
    expect(lineText(7, 9)).toBe('lines 7 to 9')
    expect(lineText(null, null)).toBeNull()
  })
})

describe('shownText', () => {
  it('counts the rows shown of all rows', () => {
    expect(shownText(54, 54)).toBe('Showing 54 of 54 items')
    expect(shownText(1, 1)).toBe('Showing 1 of 1 item')
    expect(shownText(0, 6)).toBe('Showing 0 of 6 items')
  })
})

describe('overviewText', () => {
  it('keeps the old sentence for a report with vulnerabilities only', () => {
    const kinds = { vulnerability: 492, misconfiguration: 0, secret: 0, license: 0 }
    expect(overviewText(kinds, 54)).toBe('492 findings in 54 packages')
    expect(overviewText({ ...kinds, vulnerability: 0 }, 0)).toBe('0 findings in 0 packages')
  })

  it('lists each kind that was found', () => {
    const kinds = { vulnerability: 3, misconfiguration: 2, secret: 1, license: 0 }
    expect(overviewText(kinds, 2)).toBe('6 findings: 3 vulnerabilities in 2 packages, 2 misconfigurations, 1 secret')
    expect(overviewText({ vulnerability: 0, misconfiguration: 1, secret: 0, license: 4 }, 0)).toBe(
      '5 findings: 1 misconfiguration, 4 licenses')
  })
})
