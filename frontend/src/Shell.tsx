import { Link, Outlet } from 'react-router'
import { BrandMark } from './BrandMark'
import { ThemeToggle } from './ThemeToggle'
import { APP_NAME } from './tools/usePageTitle'
import './styles/shell.css'

/** The header on every page, then the page itself. */
export function Shell() {
  return (
    <>
      <header className="app-header">
        <Link className="app-name" to="/">
          <BrandMark />
          {APP_NAME}
        </Link>
        <ThemeToggle />
      </header>
      <Outlet />
    </>
  )
}
