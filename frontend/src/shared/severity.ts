// Severity levels and their order (same rules as the backend).
import { SEVERITIES, type RatedSeverity, type Severity } from '../api/types'

// Severity levels: a higher number is more severe. UNKNOWN has no level:
// Trivy could not rate it, so it stays outside the ranking (same as the backend).
const SEVERITY_LEVELS: Record<RatedSeverity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

/** The rated severities, most severe first. */
export const RATED_SEVERITIES = SEVERITIES.filter((s): s is RatedSeverity => s !== 'UNKNOWN')

/** 4 for CRITICAL down to 1 for LOW; null for UNKNOWN (not rated). */
export function severityLevel(severity: Severity): number | null {
  return severity === 'UNKNOWN' ? null : SEVERITY_LEVELS[severity]
}

/** Below 0 when a is more severe than b; UNKNOWN comes after every rated severity. */
export function compareSeverity(a: Severity, b: Severity): number {
  const levelA = severityLevel(a)
  const levelB = severityLevel(b)
  if (levelA === null || levelB === null) return (levelA === null ? 1 : 0) - (levelB === null ? 1 : 0)
  return levelB - levelA
}

/** The most severe rated severity; UNKNOWN only when nothing is rated. */
export function worstSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>((worst, s) => (compareSeverity(s, worst) < 0 ? s : worst), 'UNKNOWN')
}

/** "Critical" for CRITICAL: calmer to read than all capitals. */
export function severityLabel(severity: Severity): string {
  return severity.charAt(0) + severity.slice(1).toLowerCase()
}
