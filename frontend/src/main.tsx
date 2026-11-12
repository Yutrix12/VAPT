import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router'
import './styles/tokens.css'
import './styles/base.css'
import './styles/severity.css'
import { appRoutes } from './App.tsx'
import { applyTheme, loadTheme } from './theme'

// Before the first paint, so a saved light or dark choice does not flash the other theme.
applyTheme(loadTheme())

// Plain browser paths (/ and /trivy): the Vite dev and preview servers answer
// every unknown path with index.html, so refresh and Back work. The /api/ proxy
// is untouched. A static host would need the same fallback.
const router = createBrowserRouter(appRoutes)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
