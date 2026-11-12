import { RATED_SEVERITIES, severityLabel } from '../../shared/severity'
import { KEV_LABEL } from '../../shared/threat'

/**
 * What a finding looks like in the Trivy viewer, on the tool's card: the five
 * severity levels and one well-known example (Log4Shell). The example is labelled as
 * one; nothing here comes from a report.
 */
export function TrivyPreview() {
  return (
    <div className="tool-preview">
      <p className="preview-label">Every finding has a severity</p>
      <ul className="preview-levels">
        {[...RATED_SEVERITIES, 'UNKNOWN' as const].map((severity) => (
          <li key={severity}>
            <span className={`badge-severity severity-${severity.toLowerCase()}`}>{severityLabel(severity)}</span>
          </li>
        ))}
      </ul>
      <p className="preview-label">Example</p>
      <div className="preview-finding">
        <div className="preview-finding-head">
          <span className="badge-severity severity-critical">{severityLabel('CRITICAL')}</span>
          <span className="badge-kev">{KEV_LABEL}</span>
        </div>
        <p className="preview-id mono">CVE-2021-44228</p>
        <dl className="preview-facts">
          <div>
            <dt>Package</dt>
            <dd className="mono">log4j-core 2.14.1</dd>
          </div>
          <div>
            <dt>Fixed version</dt>
            <dd className="mono">2.15.0</dd>
          </div>
        </dl>
      </div>
    </div>
  )
}
