import type { Summary } from '../api/types'
import { countText, RATED_SEVERITIES, severityLabel } from '../reportLogic'

/**
 * The severity rail: one bar for the rated findings, a part per severity as
 * wide as its share, and UNKNOWN apart after a gap, since Trivy could not
 * rate it. The bars are decoration; the legend says the same in text.
 */
export function SeverityCounts({ summary }: { summary: Summary }) {
  const counts = summary.by_severity
  const rated = RATED_SEVERITIES.filter((severity) => counts[severity] > 0)
  return (
    <section className="overview" aria-labelledby="counts-heading">
      <h2 id="counts-heading">
        {countText(summary.total, 'finding')} in {countText(summary.unique_packages, 'package')}
      </h2>
      <div className="rails" aria-hidden="true">
        {/* Shown as an empty track when there are no findings at all. Wide
            enough for every part, however many UNKNOWN findings there are. */}
        {(rated.length > 0 || counts.UNKNOWN === 0) && (
          <div
            className="rail"
            style={{ flexGrow: Math.max(1, summary.total - counts.UNKNOWN), minWidth: `${rated.length * 6}px` }}
          >
            {rated.map((severity) => (
              <span
                key={severity}
                className={`rail-part rail-${severity.toLowerCase()}`}
                style={{ flexGrow: counts[severity] }}
              />
            ))}
          </div>
        )}
        {counts.UNKNOWN > 0 && (
          <div className="rail" style={{ flexGrow: counts.UNKNOWN }}>
            <span className="rail-part rail-unknown" style={{ flexGrow: 1 }} />
          </div>
        )}
      </div>
      <ul className="legend">
        {RATED_SEVERITIES.map((severity) => (
          <li key={severity}>
            <span className={`swatch rail-${severity.toLowerCase()}`} aria-hidden="true" />
            <span className="legend-count">{counts[severity]}</span> {severityLabel(severity)}
          </li>
        ))}
        <li className="legend-apart">
          <span className="swatch rail-unknown" aria-hidden="true" />
          <span className="legend-count">{counts.UNKNOWN}</span> {severityLabel('UNKNOWN')} (not rated)
        </li>
      </ul>
      <p className="muted">
        {countText(summary.unique_vuln_ids, 'unique vulnerability ID')}.{' '}
        {countText(summary.without_fixed_version, 'finding')} {summary.without_fixed_version === 1 ? 'has' : 'have'} no
        fixed version yet.
      </p>
    </section>
  )
}
