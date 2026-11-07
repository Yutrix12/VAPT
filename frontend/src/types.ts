// The shapes /api/analyze returns. They mirror the Pydantic models in
// backend/main.py (ReportDetails, Summary, PackageGroupOut, AnalyzeResponse).

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const
export type Severity = (typeof SEVERITIES)[number]

export interface Finding {
  fingerprint: string
  target: string
  vuln_class: string | null
  vuln_type: string | null
  vuln_id: string | null
  pkg_name: string | null
  installed_version: string | null
  fixed_version: string | null
  status: string
  severity: Severity
  title: string | null
  cvss_score: number | null
  primary_url: string | null
  published_date: string | null
}

export interface ReportDetails {
  file_name: string
  file_sha256: string
  schema_version: number | null
  trivy_version: string | null
  created_at: string | null
  artifact_name: string | null
  artifact_type: string | null
  os_family: string | null
  os_name: string | null
  repo_url: string | null
  branch: string | null
  commit: string | null
  misconfig_count: number
  secret_count: number
}

export interface Summary {
  total: number
  by_severity: Record<Severity, number>
  by_status: Record<string, number>
  unique_vuln_ids: number
  unique_packages: number
  without_fixed_version: number
  distinct_fingerprints: number
}

export interface PackageGroup {
  target: string
  pkg_name: string | null
  installed_version: string | null
  finding_count: number
  worst_severity: Severity
  fixed_versions: string[]
  has_unfixed: boolean
  findings: Finding[]
}

export interface AnalyzeResult {
  report: ReportDetails
  summary: Summary
  package_groups: PackageGroup[]
}
