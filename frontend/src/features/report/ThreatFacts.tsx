import type { PackageGroup } from '../../api/types'
import { KEV_LABEL, hasThreatData, packageEpssText, packageKevText } from '../../shared/threat'
import { visibleText } from '../../shared/text'

/**
 * Known exploited (CISA KEV) and the highest exploit probability (EPSS) of one package,
 * over all its CVEs. Looked up by the backend from its local files, never by the AI.
 */
export function ThreatFacts({ group }: { group: PackageGroup }) {
  if (!hasThreatData(group)) return null
  const epss = packageEpssText(group.findings)
  return (
    <dl className="facts threat-facts">
      <div>
        <dt>{KEV_LABEL}</dt>
        <dd>{packageKevText(group.findings)}</dd>
      </div>
      <div>
        <dt>Highest exploit probability (EPSS)</dt>
        <dd>
          {epss.text}
          {epss.id !== null && (
            <>
              {' '}
              <span className="muted" translate="no">
                ({visibleText(epss.id)})
              </span>
            </>
          )}
        </dd>
      </div>
    </dl>
  )
}
