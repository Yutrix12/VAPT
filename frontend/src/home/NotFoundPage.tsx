import { Link } from 'react-router'
import { usePageTitle } from '../tools/usePageTitle'
import './home.css'

export function NotFoundPage() {
  usePageTitle('Page not found')
  return (
    <main className="home" id="results">
      <h1>Page not found</h1>
      <p className="muted">There is nothing at this address.</p>
      <p>
        <Link className="text-link" to="/">
          ← Home
        </Link>
      </p>
    </main>
  )
}
