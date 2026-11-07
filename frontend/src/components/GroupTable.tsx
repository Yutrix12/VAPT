import { Fragment, useState } from 'react'
import { safeLink, type ShownGroup } from '../reportLogic'
import type { Finding, PackageGroup, Severity } from '../types'

/** A unique key per group: JSON keeps null and "" apart, and needs no separator. */
function groupKey(group: PackageGroup): string {
  return JSON.stringify([group.target, group.pkg_name, group.installed_version])
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge-severity severity-${severity.toLowerCase()}`}>{severity}</span>
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
          <span className="nowrap">{version}</span>
        </Fragment>
      ))}
      {group.has_unfixed && <span className="muted"> (some CVEs have no fix yet)</span>}
    </span>
  )
}

/** The CVEs of one group (only those that match the filters). */
function CveList({ findings }: { findings: Finding[] }) {
  return (
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
          const id = finding.vuln_id ?? 'unknown ID'
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
              <td>{finding.status}</td>
              <td translate="no" className="nowrap">{finding.fixed_version ?? 'no fix yet'}</td>
              <td className="number">{finding.cvss_score ?? '–'}</td>
              <td>{finding.title ?? ''}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

/** Package groups, worst first, each expandable to its list of CVEs. */
export function GroupTable({ shown }: { shown: ShownGroup[] }) {
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
    <table className="groups">
      <thead>
        <tr>
          <th scope="col"><span className="visually-hidden">Show CVEs</span></th>
          <th scope="col">Package</th>
          <th scope="col">Installed</th>
          <th scope="col">Target</th>
          <th scope="col" className="number">Findings</th>
          <th scope="col">Worst</th>
          <th scope="col">Trivy’s fix</th>
        </tr>
      </thead>
      <tbody>
        {shown.map((item, index) => {
          const key = groupKey(item.group)
          return (
            <GroupRows
              key={key}
              item={item}
              listId={`cves-${index}`}
              isOpen={open.has(key)}
              onToggle={() => toggle(key)}
            />
          )
        })}
      </tbody>
    </table>
  )
}

interface RowProps {
  item: ShownGroup
  listId: string
  isOpen: boolean
  onToggle: () => void
}

/** One group row, plus its CVE list underneath when it is open. */
function GroupRows({ item, listId, isOpen, onToggle }: RowProps) {
  const { group, findings, worst } = item
  const name = group.pkg_name ?? 'unknown package'
  const count =
    findings.length === group.finding_count
      ? String(group.finding_count)
      : `${findings.length} of ${group.finding_count}`
  return (
    <>
      <tr>
        <td>
          <button
            type="button"
            className="expand"
            aria-expanded={isOpen}
            // Points at the CVE list only while that list exists.
            aria-controls={isOpen ? listId : undefined}
            aria-label={`${isOpen ? 'Hide' : 'Show'} CVEs of ${name}`}
            onClick={onToggle}
          >
            {isOpen ? '−' : '+'}
          </button>
        </td>
        <td translate="no">{name}</td>
        <td translate="no" className="nowrap">{group.installed_version ?? 'unknown'}</td>
        <td translate="no" className="target">{group.target}</td>
        <td className="number">{count}</td>
        <td><SeverityBadge severity={worst} /></td>
        <td><TrivyFix group={group} /></td>
      </tr>
      {isOpen && (
        <tr id={listId} className="cve-row">
          <td colSpan={7}>
            <CveList findings={findings} />
          </td>
        </tr>
      )}
    </>
  )
}
