// Plain words for the report details.

/** What the page shows for a field the uploaded format does not carry (U3). */
export const NOT_IN_FORMAT = 'not in this format'

/** "not in this format" when the report's format lacks `field`, else `value`. */
export function fieldOrNotInFormat(report: { not_in_format: string[] }, field: string, value: string): string {
  return report.not_in_format.includes(field) ? NOT_IN_FORMAT : value
}

// Trivy 0.76.2's artifact types (pkg/fanal/types/artifact.go) in plain words.
const ARTIFACT_TYPE_LABELS: Record<string, string> = {
  container_image: 'Container image',
  filesystem: 'Filesystem',
  repository: 'Repository',
  cyclonedx: 'CycloneDX SBOM',
  spdx: 'SPDX SBOM',
  aws_account: 'AWS account',
  vm: 'Virtual machine image',
}

/** "Container image" for container_image; any other value as Trivy wrote it. */
export function artifactTypeLabel(type: string | null): string {
  if (type === null) return 'unknown'
  return Object.hasOwn(ARTIFACT_TYPE_LABELS, type) ? ARTIFACT_TYPE_LABELS[type] : type
}
