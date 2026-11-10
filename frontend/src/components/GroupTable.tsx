import { Fragment, useState } from 'react'
import { groupKey, safeLink, severityLabel, visibleText, type ShownGroup } from '../reportLogic'
import { FixPanel } from './FixPanel'
import type { AiConnection, Finding, FixState, PackageGroup, Severity } from '../types'

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge-severity severity-${severity.toLowerCase()}`}>{severityLabel(severity)}</span>
}

/** A small arrow that turns when the row opens (CSS does the turning). */
function Chevron() {
  return (
    <svg className="chevron" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">
      <path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Trivy's own fix for a group: its fixed versions, or "no fix available yet". */
function TrivyFix({ group }: { group: PackageGroup }) {
  if (group.fixed_versions.length === 0) return <span className="no-fix">no fix available yet</span>
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
      {group.has_unfixed && <span className="muted"> (some CVEs have no fix yet)</span>}
    </span>
  )
}

/** The CVEs of one group (only those that match the filters). */
function CveList({ findings }: { findings: Finding[] }) {
  return (
    <div className="table-scroll">
      <table className="cves">
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Severity</th>
            <th scope="col">Status</th>
            <th scope="col">Fixed in</th>
            <th scope="col">CVSS</th>
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
                <td translate="no" className="nowrap code">{visibleText(finding.fixed_version ?? 'no fix yet')}</td>
                <td className="number">{finding.cvss_score ?? '–'}</td>
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
  shown: ShownGroup[]
  connection: AiConnection
  fixFor: (group: PackageGroup) => FixState | undefined
  onExplain: (group: PackageGroup) => void
}

/** Package groups, worst first; opening one shows its AI explanation and CVEs. */
export function GroupTable({ shown, connection, fixFor, onExplain }: TableProps) {
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set())

  function toggle(key: string) {
    setOpen((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  if (shown.length === 0) return <p className="muted">No package group matches the filters.</p>

  return (
    <div className="table-scroll">
      {/* Explicit roles: the narrow-screen card layout changes display, which
      would otherwise drop the table semantics. */}
      <table className="groups" role="table">
        <thead role="rowgroup">
          <tr role="row">
            <th role="columnheader" scope="col">Package</th>
            <th role="columnheader" scope="col">Installed</th>
            <th role="columnheader" scope="col">Target</th>
            <th role="columnheader" scope="col" className="number">Findings</th>
            <th role="columnheader" scope="col">Worst</th>
            <th role="columnheader" scope="col">Trivy’s fix</th>
          </tr>
        </thead>
        <tbody role="rowgroup">
          {shown.map((item, index) => {
            const key = groupKey(item.group)
            return (
              <GroupRows
                key={key}
                item={item}
                listId={`cves-${index}`}
                isOpen={open.has(key)}
                onToggle={() => toggle(key)}
                connection={connection}
                fix={fixFor(item.group)}
                onExplain={() => onExplain(item.group)}
              />
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface RowProps {
  item: ShownGroup
  listId: string
  isOpen: boolean
  onToggle: () => void
  connection: AiConnection
  fix: FixState | undefined
  onExplain: () => void
}

/** One group row, plus its AI advice and CVE list underneath when it is open. */
function GroupRows({ item, listId, isOpen, onToggle, connection, fix, onExplain }: RowProps) {
  const { group, findings, worst } = item
  const name = visibleText(group.pkg_name ?? 'unknown package')
  const count =
    findings.length === group.finding_count
      ? String(group.finding_count)
      : `${findings.length} of ${group.finding_count}`
  return (
    <>
      <tr role="row" className={`group-row worst-${worst.toLowerCase()}${isOpen ? ' is-open' : ''}`}>
        <td role="cell">
          <button
            type="button"
            className="row-toggle"
            aria-expanded={isOpen}
            // Points at the details only while they exist.
            aria-controls={isOpen ? listId : undefined}
            onClick={onToggle}
          >
            <Chevron />
            <span translate="no">{name}</span>
          </button>
        </td>
        {/* data-label names each cell when narrow screens show a row as a card. */}
        <td role="cell" translate="no" className="nowrap code" data-label="Installed">
          {visibleText(group.installed_version ?? 'unknown')}
        </td>
        <td role="cell" translate="no" className="target" data-label="Target">
          {visibleText(group.target)}
        </td>
        <td role="cell" className="number" data-label="Findings">
          {count}
        </td>
        <td role="cell" data-label="Worst">
          <SeverityBadge severity={worst} />
        </td>
        <td role="cell" className="fix-cell" data-label="Trivy’s fix">
          <TrivyFix group={group} />
        </td>
      </tr>
      {isOpen && (
        <tr role="row" id={listId} className={`detail-row worst-${worst.toLowerCase()}`}>
          <td role="cell" colSpan={6}>
            <FixPanel fix={fix} connection={connection} onExplain={onExplain} />
            <CveList findings={findings} />
          </td>
        </tr>
      )}
    </>
  )
}
