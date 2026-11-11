import { describe, expect, it } from 'vitest'
import { artifactTypeLabel, fieldOrNotInFormat } from './reportText'

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
