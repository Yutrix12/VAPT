// The shapes /api/analyze returns. They mirror the Pydantic models in
// backend/app/api/schemas.py (ReportDetails, Summary, PackageGroupOut, the finding
// kinds, AnalyzeResponse).

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const // display order
export type Severity = (typeof SEVERITIES)[number]
/** The severities Trivy could rate; UNKNOWN is kept outside the ranking. */
export type RatedSeverity = Exclude<Severity, 'UNKNOWN'>

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
  report_format: string // e.g. "Trivy JSON", detected by the backend from the content
  not_in_format: string[] // fields this format does not carry
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
  by_kind: Record<string, number> // vulnerability, misconfiguration, secret, license
  misconfig_passed: number
  misconfig_exceptions: number
}

/** One failed configuration check. The backend never sends its Message or code lines. */
export interface Misconfiguration {
  fingerprint: string
  target: string
  misconf_type: string | null
  check_type: string | null
  check_id: string | null
  title: string | null
  description: string | null
  resolution: string | null // Trivy's own fix text; null when the report has none
  severity: Severity
  status: string
  primary_url: string | null
  references: string[]
  resource: string | null
  start_line: number | null
  end_line: number | null
}

/** Where a secret is. There is no field for its value: it never reaches the page. */
export interface Secret {
  fingerprint: string
  target: string
  rule_id: string | null
  category: string | null
  severity: Severity
  title: string | null
  start_line: number | null
  end_line: number | null
}

export interface License {
  fingerprint: string
  target: string
  license_class: string | null
  pkg_name: string | null
  file_path: string | null
  name: string | null
  category: string | null
  severity: Severity
  confidence: number | null
  link: string | null
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
  misconfigurations: Misconfiguration[]
  secrets: Secret[]
  licenses: License[]
  secret_fix_steps: string[] // the same fixed steps for every secret
}

/** The AI explanation of one package group in the page; undefined means not asked yet. */
export type FixState =
  | { state: 'queued' } // waiting while another explanation runs
  | { state: 'loading'; startedAt: number }
  | { state: 'done'; advice: FixAdvice }
  | { state: 'error'; message: string }

/** Whether AI explanations can run: the backend's LLM answers and has its model. */
export type AiConnection =
  | { state: 'checking' }
  | { state: 'ready'; model: string; leavesThisComputer: boolean }
  | { state: 'error'; message: string }

/** POST /api/llm/check. The backend chooses the LLM; the page never sends settings. */
export interface LlmStatus {
  model: string
  model_found: boolean
  leaves_this_computer: boolean
}

// /api/fix request body "group" (backend/app/fixes/schemas.py FixGroup).
export interface FixGroupRequest {
  target: string
  pkg_name: string | null
  installed_version: string | null
  ecosystem: string | null
  os: string | null
  fixed_versions: string[]
  cves: { vuln_id: string; severity: Severity; title: string | null; fixed_version: string | null }[]
}

export const FIX_STATUSES = ['verified', 'unverified', 'no_version_suggested', 'no_fix_available'] as const
export type FixStatus = (typeof FIX_STATUSES)[number]

// /api/fix answer (backend/app/fixes/schemas.py FixAdvice). The code, not the model,
// set `status`: target_version is set only when it is one of Trivy's.
export interface FixAdvice {
  status: FixStatus
  target_version: string | null
  unverified_version: string | null
  trivy_fixed_versions: string[]
  mitigation_only: boolean
  cves_without_fix: number
  summary: string
  recommended_action: string
  commands: string[]
  risk_notes: string
  disclaimer: string
}
