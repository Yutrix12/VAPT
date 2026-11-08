import { countText, formatScanDate, visibleText } from '../reportLogic'
import type { ReportDetails as Details } from '../types'

/** What was scanned: the artifact as the title, then the facts about the scan. */
export function ReportDetails({ report }: { report: Details }) {
  const isRepository = report.artifact_type === 'repository'
  const hasGit = Boolean(report.repo_url || report.branch || report.commit)
  const os = [report.os_family, report.os_name].filter(Boolean).join(' ')

  return (
    <section aria-labelledby="details-heading">
      <h2 id="details-heading" className="report-title" translate="no">
        {visibleText(report.artifact_name ?? 'Unknown artifact')}
      </h2>
      <dl className="facts">
        <div>
          <dt>Type</dt>
          <dd translate="no">{visibleText(report.artifact_type ?? 'unknown')}</dd>
        </div>
        {isRepository ? (
          <>
            <div className="wide-fact">
              <dt>Repository</dt>
              <dd translate="no">{hasGit ? visibleText(report.repo_url ?? 'unknown') : 'no git details in report'}</dd>
            </div>
            {hasGit && (
              <>
                <div>
                  <dt>Branch</dt>
                  <dd translate="no">{visibleText(report.branch ?? 'unknown')}</dd>
                </div>
                <div className="wide-fact">
                  <dt>Commit</dt>
                  <dd translate="no" className="code">
                    {visibleText(report.commit ?? 'unknown')}
                  </dd>
                </div>
              </>
            )}
          </>
        ) : (
          <div>
            <dt>Operating system</dt>
            <dd translate="no">{visibleText(os || 'unknown')}</dd>
          </div>
        )}
        <div>
          <dt>Scanned</dt>
          <dd>{visibleText(formatScanDate(report.created_at))}</dd>
        </div>
        <div>
          <dt>Trivy</dt>
          <dd translate="no">{visibleText(report.trivy_version ?? 'unknown')}</dd>
        </div>
        <div>
          <dt>File</dt>
          <dd translate="no">{visibleText(report.file_name)}</dd>
        </div>
        <div>
          <dt>Also found</dt>
          <dd>
            {countText(report.misconfig_count, 'misconfiguration')}, {countText(report.secret_count, 'secret')}{' '}
            (counted only)
          </dd>
        </div>
      </dl>
    </section>
  )
}
