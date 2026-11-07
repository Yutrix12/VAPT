import { countText, formatScanDate } from '../reportLogic'
import type { ReportDetails as Details } from '../types'

/** What was scanned: artifact, Trivy version, date, and OS or repository. */
export function ReportDetails({ report }: { report: Details }) {
  const isRepository = report.artifact_type === 'repository'
  const hasGit = Boolean(report.repo_url || report.branch || report.commit)
  const os = [report.os_family, report.os_name].filter(Boolean).join(' ')

  return (
    <section aria-labelledby="details-heading">
      <h2 id="details-heading">Report</h2>
      <dl className="details">
        <dt>File</dt>
        <dd translate="no">{report.file_name}</dd>
        <dt>Scanned</dt>
        <dd translate="no">
          {report.artifact_name ?? 'unknown'} ({report.artifact_type ?? 'unknown type'})
        </dd>
        <dt>Trivy version</dt>
        <dd translate="no">{report.trivy_version ?? 'unknown'}</dd>
        <dt>Scan date</dt>
        <dd>{formatScanDate(report.created_at)}</dd>
        {isRepository ? (
          <>
            <dt>Repository</dt>
            <dd translate="no">{hasGit ? (report.repo_url ?? 'unknown') : 'no git details in report'}</dd>
            {hasGit && (
              <>
                <dt>Branch</dt>
                <dd translate="no">{report.branch ?? 'unknown'}</dd>
                <dt>Commit</dt>
                <dd translate="no">{report.commit ?? 'unknown'}</dd>
              </>
            )}
          </>
        ) : (
          <>
            <dt>Operating system</dt>
            <dd translate="no">{os || 'unknown'}</dd>
          </>
        )}
        <dt>Also found</dt>
        <dd>
          {countText(report.misconfig_count, 'misconfiguration')},{' '}
          {countText(report.secret_count, 'secret')} (counted only)
        </dd>
      </dl>
    </section>
  )
}
