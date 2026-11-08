import { countText, severityLabel } from '../reportLogic'
import { SEVERITIES, type Summary } from '../types'

/**
 * The severity rail: one bar with a part per severity, as wide as its share
 * of the findings. The bar is decoration; the legend says the same in text.
 */
export function SeverityCounts({ summary }: { summary: Summary }) {
  return (
    <section className="overview" aria-labelledby="counts-heading">
      <h2 id="counts-heading">
        {countText(summary.total, 'finding')} in {countText(summary.unique_packages, 'package')}
      </h2>
      <div className="rail" aria-hidden="true">
        {SEVERITIES.filter((severity) => summary.by_severity[severity] > 0).map((severity) => (
          <span
            key={severity}
            className={`rail-part rail-${severity.toLowerCase()}`}
            style={{ flexGrow: summary.by_severity[severity] }}
          />
        ))}
      </div>
      <ul className="legend">
        {SEVERITIES.map((severity) => (
          <li key={severity}>
            <span className={`swatch rail-${severity.toLowerCase()}`} aria-hidden="true" />
            <span className="legend-count">{summary.by_severity[severity]}</span> {severityLabel(severity)}
          </li>
        ))}
      </ul>
      <p className="muted">
        {countText(summary.unique_vuln_ids, 'distinct vulnerability ID')};{' '}
        {countText(summary.without_fixed_version, 'finding')} without a fixed version yet.
      </p>
    </section>
  )
}
