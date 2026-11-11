import { Fragment, useState, type ReactNode } from 'react'
import type { AiConnection, Finding, FixState, OtherFixState, PackageGroup, Severity } from '../../api/types'
import { severityLabel } from '../../shared/severity'
import { NOT_IN_FORMAT, kindLabel, lineText, misconfigurationName, secretName } from '../../shared/reportText'
import { safeLink, visibleText } from '../../shared/text'
import { EPSS_LABEL, KEV_LABEL, epssCellText, hasThreatData, kevCellText, kevCount } from '../../shared/threat'
import { FixCommands } from '../fixes/FixCommands'
import { FixPanel } from '../fixes/FixPanel'
import { DetailsDialog } from './DetailsDialog'
import { LicenseDetails, MisconfigurationDetails, SecretDetails } from './KindDetails'
import type { OtherRow, Row } from './rows'
import { ThreatFacts } from './ThreatFacts'

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge-severity severity-${severity.toLowerCase()}`}>{severityLabel(severity)}</span>
}

/** Trivy's fixed versions for a package, or "No fixed version yet". */
function TrivyFix({ group }: { group: PackageGroup }) {
  if (group.fixed_versions.length === 0) return <span className="no-fix">No fixed version yet</span>
  return (
    <span translate="no">
      {group.fixed_versions.map((version, index) => (
        // A version never breaks in the middle (e.g. at its "-"); the line
        // may break at the ", " between versions, so it stays outside.
        <Fragment key={version}>
          {index > 0 && ', '}
          <span className="nowrap code">{visibleText(version)}</span>
        </Fragment>
      ))}
      {group.has_unfixed && <span className="muted"> (some vulnerabilities have no fixed version yet)</span>}
    </span>
  )
}

/** The vulnerabilities of one package (only those that match the filters). */
function CveList({ findings, withThreat }: { findings: Finding[]; withThreat: boolean }) {
  return (
    <div className="table-scroll">
      <table className="cves">
        <thead>
          <tr>
            <th scope="col">CVE ID</th>
            <th scope="col">Severity</th>
            <th scope="col">Status</th>
            <th scope="col">Fixed version</th>
            <th scope="col">CVSS score</th>
            {withThreat && <th scope="col">{KEV_LABEL}</th>}
            {withThreat && <th scope="col">{EPSS_LABEL}</th>}
            <th scope="col">Title</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => {
            const link = safeLink(finding.primary_url)
            const id = visibleText(finding.vuln_id ?? 'unknown ID')
            return (
              // Fingerprints repeat for duplicate rows, so the index is part of the key.
              <tr key={`${finding.fingerprint}-${index}`}>
                <td translate="no" className="nowrap">
                  {link ? (
                    <a href={link} target="_blank" rel="noopener noreferrer">
                      {id}
                    </a>
                  ) : (
                    id
                  )}
                </td>
                <td><SeverityBadge severity={finding.severity} /></td>
                <td>{visibleText(finding.status)}</td>
                <td translate="no" className="nowrap code">{visibleText(finding.fixed_version ?? 'No fixed version yet')}</td>
                <td className="number">{finding.cvss_score ?? '–'}</td>
                {withThreat && <td>{kevCellText(finding.threat)}</td>}
                {withThreat && <td className="number">{epssCellText(finding.threat)}</td>}
                <td>{visibleText(finding.title ?? '')}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface TableProps {
  rows: Row[]
  notInFormat: string[] // fields the report's format lacks
  secretFixSteps: string[]
  connection: AiConnection
  fixFor: (group: PackageGroup) => FixState | undefined
  onExplain: (group: PackageGroup) => void
  otherFixFor: (row: OtherRow) => OtherFixState | undefined
  onExplainOther: (row: OtherRow) => void
}

/** A text cut at a space once it is longer than `max`, with " ..." at the end. */
function shorten(text: string, max = 80): string {
  if (text.length <= max) return text
  const space = text.lastIndexOf(' ', max)
  return `${text.slice(0, space > 0 ? space : max)} ...`
}

/** Every finding kind in one table, worst first; "View details" opens a finding in a dialog. */
export function FindingsTable({
  rows,
  notInFormat,
  secretFixSteps,
  connection,
  fixFor,
  onExplain,
  otherFixFor,
  onExplainOther,
}: TableProps) {
  // The key of the finding whose dialog is open; the dialog closes by itself (Esc, Close, backdrop).
  const [openKey, setOpenKey] = useState<string | null>(null)
  const openRow = rows.find((row) => row.key === openKey)

  if (rows.length === 0) return <p className="muted">No finding matches the filters.</p>

  return (
    <div className="table-scroll">
      {/* Explicit roles: the narrow-screen card layout changes display, which
      would otherwise drop the table semantics. */}
      <table className="groups" role="table">
        <thead role="rowgroup">
          <tr role="row">
            <th role="columnheader" scope="col">Item</th>
            <th role="columnheader" scope="col">Kind</th>
            <th role="columnheader" scope="col">Where</th>
            <th role="columnheader" scope="col" className="number">Findings</th>
            <th role="columnheader" scope="col">Highest severity</th>
            <th role="columnheader" scope="col">Fix</th>
          </tr>
        </thead>
        <tbody role="rowgroup">
          {rows.map((row) => (
            <FindingRow
              key={row.key}
              row={row}
              notInFormat={notInFormat}
              secretFixSteps={secretFixSteps}
              onOpen={() => setOpenKey(row.key)}
            />
          ))}
        </tbody>
      </table>
      {openRow !== undefined && (
        <DetailsDialog
          key={openRow.key}
          title={cellsOf(openRow, secretFixSteps, notInFormat).name}
          subtitle={
            <>
              {kindLabel(openRow.kind)} <SeverityBadge severity={openRow.severity} />
            </>
          }
          onClose={() => setOpenKey(null)}
        >
          {openRow.kind === 'vulnerability' && (
            <>
              <ThreatFacts group={openRow.shown.group} />
              <FixCommands commands={openRow.shown.group.fix_commands} note={openRow.shown.group.fix_commands_note} />
              <FixPanel
                fix={fixFor(openRow.shown.group)}
                connection={connection}
                onExplain={() => onExplain(openRow.shown.group)}
              />
              <CveList findings={openRow.shown.findings} withThreat={hasThreatData(openRow.shown.group)} />
            </>
          )}
          {openRow.kind === 'misconfiguration' && <MisconfigurationDetails item={openRow.item} notInFormat={notInFormat} />}
          {openRow.kind === 'secret' && <SecretDetails item={openRow.item} steps={secretFixSteps} />}
          {openRow.kind === 'license' && <LicenseDetails item={openRow.item} />}
          {openRow.kind !== 'vulnerability' && (
            // The built-in details and fix come first; the AI explanation adds to them.
            <FixPanel
              fix={otherFixFor(openRow)}
              connection={connection}
              onExplain={() => onExplainOther(openRow)}
              fallback="The details above still apply."
            />
          )}
        </DetailsDialog>
      )}
    </div>
  )
}

interface RowProps {
  row: Row
  notInFormat: string[]
  secretFixSteps: string[]
  onOpen: () => void
}

/** What a row shows in its cells, whatever the kind. */
interface Cells {
  name: string
  where: ReactNode
  count: string
  fix: ReactNode
}

function whereCell(main: string, sub: string | null): ReactNode {
  return (
    <>
      {visibleText(main)}
      {sub !== null && <span className="muted where-sub">{visibleText(sub)}</span>}
    </>
  )
}

function cellsOf(row: Row, secretFixSteps: string[], notInFormat: string[]): Cells {
  switch (row.kind) {
    case 'vulnerability': {
      const { group, findings } = row.shown
      return {
        name: group.pkg_name ?? 'unknown package',
        where: (
          <>
            <span className="nowrap code">{visibleText(group.installed_version ?? 'unknown')}</span>
            <span className="muted where-sub">{visibleText(group.target)}</span>
          </>
        ),
        count:
          findings.length === group.finding_count
            ? String(group.finding_count)
            : `${findings.length} of ${group.finding_count}`,
        fix: <TrivyFix group={group} />,
      }
    }
    case 'misconfiguration': {
      const { item } = row
      const missing = notInFormat.includes('resolution') ? NOT_IN_FORMAT : 'No fix text in this report'
      return {
        name: misconfigurationName(item),
        where: whereCell(item.target, lineText(item.start_line, item.end_line)),
        count: '1',
        fix:
          item.resolution === null ? <span className="muted">{missing}</span> : visibleText(shorten(item.resolution)),
      }
    }
    case 'secret': {
      const { item } = row
      return {
        name: secretName(item),
        where: whereCell(item.target, lineText(item.start_line, item.end_line)),
        count: '1',
        fix: visibleText(shorten(secretFixSteps[0] ?? 'See the details')),
      }
    }
    case 'license': {
      const { item } = row
      return {
        name: item.name ?? 'unknown license',
        where: whereCell(item.pkg_name ?? item.file_path ?? 'unknown', item.target),
        count: '1',
        fix: `Category: ${item.category ?? 'unknown'}. Ask your legal team.`,
      }
    }
  }
}

/** One row of the table, with the button that opens its details under the item name. */
function FindingRow({ row, notInFormat, secretFixSteps, onOpen }: RowProps) {
  const cells = cellsOf(row, secretFixSteps, notInFormat)
  return (
    <tr role="row" className={`group-row worst-${row.severity.toLowerCase()}`}>
      <td role="cell" className="item-name">
        <span translate="no">{visibleText(cells.name)}</span>
        {row.kind === 'vulnerability' && kevCount(row.shown.group.findings) > 0 && (
          <span className="badge-kev">{KEV_LABEL}</span>
        )}
        <button type="button" className="secondary details-button" aria-haspopup="dialog" onClick={onOpen}>
          View details
          <span className="visually-hidden"> of {visibleText(cells.name)}</span>
        </button>
      </td>
      {/* data-label names each cell when narrow screens show a row as a card. */}
      <td role="cell" className="nowrap" data-label="Kind">
        {kindLabel(row.kind)}
      </td>
      <td role="cell" translate="no" className="target" data-label="Where">
        {cells.where}
      </td>
      <td role="cell" className="number" data-label="Findings">
        {cells.count}
      </td>
      <td role="cell" data-label="Highest severity">
        <SeverityBadge severity={row.severity} />
      </td>
      <td role="cell" className="fix-cell" data-label="Fix">
        {cells.fix}
      </td>
    </tr>
  )
}
