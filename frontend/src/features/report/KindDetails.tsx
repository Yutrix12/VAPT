import type { ReactNode } from 'react'
import type { License, Misconfiguration, Secret } from '../../api/types'
import { NOT_IN_FORMAT, lineText, misconfigurationName } from '../../shared/reportText'
import { safeLink, visibleText } from '../../shared/text'

/** One labelled fact; wide ones take a whole line. */
function Fact({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? 'wide-fact' : undefined}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

/** A link only if the address is plain http(s); otherwise nothing. */
function Link({ url, children }: { url: string | null; children: string }) {
  const href = safeLink(url)
  if (href === null) return null
  return (
    <Fact label="More information" wide>
      <a href={href} target="_blank" rel="noopener noreferrer">
        {children}
      </a>
    </Fact>
  )
}

function where(target: string, start: number | null, end: number | null): string {
  const lines = lineText(start, end)
  return lines === null ? target : `${target}, ${lines}`
}

/** The details of a failed configuration check: what is wrong and Trivy's own fix text. */
export function MisconfigurationDetails({ item, notInFormat }: { item: Misconfiguration; notInFormat: string[] }) {
  const noResolution = notInFormat.includes('resolution') ? NOT_IN_FORMAT : 'The report has no fix text for this check.'
  return (
    <div className="kind-details">
      <dl className="facts">
        <Fact label="Check" wide>
          <span translate="no">{visibleText(misconfigurationName(item))}</span>
        </Fact>
        <Fact label="What is wrong" wide>
          {visibleText(item.description ?? 'The report gives no description.')}
        </Fact>
        <Fact label="How to fix it (Trivy)" wide>
          {visibleText(item.resolution ?? noResolution)}
        </Fact>
        <Fact label="Where" wide>
          <span translate="no">{visibleText(where(item.target, item.start_line, item.end_line))}</span>
        </Fact>
        <Link url={item.primary_url ?? item.references[0] ?? null}>About this check</Link>
      </dl>
    </div>
  )
}

/** The details of a secret: where it is and the fixed steps. Its value is never here. */
export function SecretDetails({ item, steps }: { item: Secret; steps: string[] }) {
  return (
    <div className="kind-details">
      <dl className="facts">
        <Fact label="Rule" wide>
          <span translate="no">{visibleText([item.rule_id, item.title].filter(Boolean).join(': ') || 'unknown rule')}</span>
        </Fact>
        <Fact label="Category">{visibleText(item.category ?? 'unknown')}</Fact>
        <Fact label="Where" wide>
          <span translate="no">{visibleText(where(item.target, item.start_line, item.end_line))}</span>
        </Fact>
      </dl>
      <div className="fix-panel">
        <h3 className="fix-title">How to fix it</h3>
        <ol>
          {steps.map((step, index) => (
            <li key={`${index}-${step}`}>{visibleText(step)}</li>
          ))}
        </ol>
        <p className="muted">The secret itself is never shown here, sent to the AI or written to the fix summary.</p>
      </div>
    </div>
  )
}

/** The details of a license: its name and category, with a pointer to the legal team. */
export function LicenseDetails({ item }: { item: License }) {
  return (
    <div className="kind-details">
      <dl className="facts">
        <Fact label="License" wide>
          <span translate="no">{visibleText(item.name ?? 'unknown license')}</span>
        </Fact>
        <Fact label="Category">{visibleText(item.category ?? 'unknown')}</Fact>
        <Fact label="Found in" wide>
          <span translate="no">{visibleText(item.pkg_name ?? item.file_path ?? 'unknown')}</span>, {visibleText(item.target)}
        </Fact>
        <Link url={item.link}>About this license</Link>
      </dl>
      <p className="muted">
        Ask your legal or compliance team what this license means for you. This page lists it and does not judge it.
      </p>
    </div>
  )
}
