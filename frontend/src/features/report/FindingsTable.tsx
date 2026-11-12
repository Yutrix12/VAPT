import { useState, type ReactNode } from 'react'
import type { AiConnection, FixState, OtherFixState, PackageGroup, Severity } from '../../api/types'
import { severityLabel } from '../../shared/severity'
import { NOT_IN_FORMAT, kindLabel, lineText, misconfigurationName, secretName } from '../../shared/reportText'
import { visibleText } from '../../shared/text'
import { KEV_LABEL, kevCount } from '../../shared/threat'
import { FixPanel } from '../fixes/FixPanel'
import { DetailsDialog } from './DetailsDialog'
import { LicenseDetails, MisconfigurationDetails, SecretDetails, VulnerabilityDetails } from './KindDetails'
import type { OtherRow, Row } from './rows'

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge-severity severity-${severity.toLowerCase()}`}>{severityLabel(severity)}</span>
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
            <th role="columnheader" scope="col">Severity</th>
            <th role="columnheader" scope="col">Item</th>
            <th role="columnheader" scope="col">Kind</th>
            <th role="columnheader" scope="col">Where</th>
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
              <VulnerabilityDetails group={openRow.shown.group} finding={openRow.shown.findings[0]} />
              {/* The AI advice is per package (asked once, shared by all its CVEs). */}
              <h3 className="fix-title">
                AI advice for the package{' '}
                <span translate="no">{visibleText(openRow.shown.group.pkg_name ?? 'unknown package')}</span>
                {' '}({openRow.shown.group.finding_count} {openRow.shown.group.finding_count === 1 ? 'CVE' : 'CVEs'})
              </h3>
              <FixPanel
                fix={fixFor(openRow.shown.group)}
                connection={connection}
                onExplain={() => onExplain(openRow.shown.group)}
              />
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
      // One CVE: its own ID, severity and fixed version.
      const { group } = row.shown
      const [finding] = row.shown.findings
      return {
        name: finding.vuln_id ?? 'unknown ID',
        where: (
          <>
            {visibleText(group.pkg_name ?? 'unknown package')}{' '}
            <span className="nowrap code">{visibleText(group.installed_version ?? 'unknown')}</span>
            <span className="muted where-sub">{visibleText(group.target)}</span>
          </>
        ),
        fix: finding.fixed_version ? (
          <span translate="no" className="code">{visibleText(finding.fixed_version)}</span>
        ) : (
          <span className="no-fix">No fixed version yet</span>
        ),
      }
    }
    case 'misconfiguration': {
      const { item } = row
      const missing = notInFormat.includes('resolution') ? NOT_IN_FORMAT : 'No fix text in this report'
      return {
        name: misconfigurationName(item),
        where: whereCell(item.target, lineText(item.start_line, item.end_line)),
        fix:
          item.resolution === null ? <span className="muted">{missing}</span> : visibleText(shorten(item.resolution)),
      }
    }
    case 'secret': {
      const { item } = row
      return {
        name: secretName(item),
        where: whereCell(item.target, lineText(item.start_line, item.end_line)),
        fix: visibleText(shorten(secretFixSteps[0] ?? 'See the details')),
      }
    }
    case 'license': {
      const { item } = row
      return {
        name: item.name ?? 'unknown license',
        where: whereCell(item.pkg_name ?? item.file_path ?? 'unknown', item.target),
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
      <td role="cell" className="sev-cell" data-label="Severity">
        <SeverityBadge severity={row.severity} />
      </td>
      <td role="cell" className="item-name">
        <span translate="no">{visibleText(cells.name)}</span>
        {row.kind === 'vulnerability' && kevCount(row.shown.findings) > 0 && (
          <span className="badge-kev">{KEV_LABEL}</span>
        )}
        <button type="button" className="secondary details-button" aria-haspopup="dialog" onClick={onOpen}>
          View details
          <span className="visually-hidden"> of {visibleText(cells.name)}</span>
        </button>
      </td>
      {/* data-label names each cell when narrow screens show a row as a card. */}
      <td role="cell" className="kind-cell" data-label="Kind">
        {kindLabel(row.kind)}
      </td>
      <td role="cell" translate="no" className="target" data-label="Where">
        {cells.where}
      </td>
      <td role="cell" className="fix-cell" data-label="Fix">
        {cells.fix}
      </td>
    </tr>
  )
}
