import { Link } from 'react-router'

/** The way back to Home; says the report goes away only when there is one. */
export function BackToTools({ reportLoaded }: { reportLoaded: boolean }) {
  return (
    <nav className="back-nav" aria-label="Tools">
      <Link className="back-link" to="/">
        <span aria-hidden="true">←</span> All tools
      </Link>
      {reportLoaded && (
        <p className="muted back-note">The loaded report is not saved; leaving this page clears it.</p>
      )}
    </nav>
  )
}
