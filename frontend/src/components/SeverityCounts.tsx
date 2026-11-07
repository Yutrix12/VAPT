import { countText } from '../reportLogic'
import { SEVERITIES, type Summary } from '../types'

/** One count per severity, worst first. The label is text, not only colour. */
export function SeverityCounts({ summary }: { summary: Summary }) {
  return (
    <section aria-labelledby="counts-heading">
      <h2 id="counts-heading">
        {countText(summary.total, 'finding')} in {countText(summary.unique_packages, 'package')}
      </h2>
      <ul className="counts">
        {SEVERITIES.map((severity) => (
          <li key={severity} className={`count severity-${severity.toLowerCase()}`}>
            <span className="count-number">{summary.by_severity[severity]}</span>
            <span className="count-label">{severity}</span>
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
