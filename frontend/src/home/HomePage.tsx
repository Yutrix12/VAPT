import type { PointerEvent } from 'react'
import { Link } from 'react-router'
import { tools as registry, type Tool } from '../tools/registry'
import { APP_NAME, usePageTitle } from '../tools/usePageTitle'
import { BrandMark } from '../BrandMark'
import { ToolIcon } from './ToolIcon'
import './home.css'

/** Moves the soft light on a card to the pointer. It sets CSS variables directly: no state, no re-render. */
function followPointer(event: PointerEvent<HTMLElement>) {
  const box = event.currentTarget.getBoundingClientRect()
  event.currentTarget.style.setProperty('--mx', `${event.clientX - box.left}px`)
  event.currentTarget.style.setProperty('--my', `${event.clientY - box.top}px`)
}

function ToolCard({ tool }: { tool: Tool }) {
  const Preview = tool.preview
  const body = (
    <>
      <div className="tool-main">
        <ToolIcon name={tool.icon} />
        <h3>{tool.name}</h3>
        <p className="tool-desc">{tool.description}</p>
      </div>
      {Preview !== undefined && <Preview />}
      {tool.steps !== undefined && (
        <dl className="tool-steps">
          {tool.steps.map((step) => (
            <div key={step.name}>
              <dt>{step.name}</dt>
              <dd>{step.text}</dd>
            </div>
          ))}
        </dl>
      )}
    </>
  )
  if (tool.status === 'ready') {
    return (
      <li className={Preview === undefined ? undefined : 'tool-featured'}>
        <Link className="tool-card" to={tool.path} onPointerMove={followPointer}>
          {body}
          <span className="tool-open">
            Open <span aria-hidden="true">→</span>
          </span>
        </Link>
      </li>
    )
  }
  return (
    <li>
      <div className="tool-card tool-card-soon">
        {body}
        <span className="tool-open">Coming soon</span>
      </div>
    </li>
  )
}

/** The home page: the name of the platform, then one card per tool in the registry. */
export function HomePage({ tools = registry }: { tools?: readonly Tool[] }) {
  usePageTitle()
  return (
    <main className="home" id="results">
      <section className="hero" aria-labelledby="home-title">
        {/* Ambient colour behind the headline: decoration only, hidden from screen readers. */}
        <div className="hero-backdrop" aria-hidden="true">
          <span className="hero-blob hero-blob-a" />
          <span className="hero-blob hero-blob-b" />
          <span className="hero-blob hero-blob-c" />
        </div>
        <BrandMark className="hero-mark rise" />
        <h1 id="home-title" className="rise">
          {APP_NAME}
        </h1>
        <p className="hero-lead rise">One place for the tools that read vulnerability scans.</p>
        <dl className="principles rise">
          <div>
            <dt>Runs on your computer</dt>
            <dd>Reports are read by a server on your own machine.</dd>
          </div>
          <div>
            <dt>Nothing is saved</dt>
            <dd>A report stays in the page until you leave it. There is no database and no history.</dd>
          </div>
        </dl>
      </section>

      <section className="tools rise" aria-labelledby="tools-title">
        <h2 id="tools-title">Tools</h2>
        <ul className="tool-row">
          {tools.map((tool) => (
            <ToolCard key={tool.id} tool={tool} />
          ))}
          {tools.length === 1 && (
            <li className="tool-slot">
              <div className="tool-card tool-card-soon tool-card-placeholder">
                <p className="tool-desc">More tools will appear here</p>
              </div>
            </li>
          )}
        </ul>
      </section>
    </main>
  )
}
