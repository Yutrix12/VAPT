import { useState } from 'react'
import { applyTheme, loadTheme, nextTheme, saveTheme, themeLabel, type Theme } from './theme'

/** The theme button in the header: Auto (system), Light, Dark. */
export function ThemeToggle() {
  // The saved choice (main.tsx has already applied it before the first paint).
  const [theme, setTheme] = useState<Theme>(loadTheme)

  function change() {
    const next = nextTheme(theme)
    setTheme(next)
    applyTheme(next)
    saveTheme(next)
  }

  return (
    <button type="button" className="secondary theme-toggle" onClick={change}>
      Theme: {themeLabel(theme)}
      <span className="visually-hidden">. Switch to {themeLabel(nextTheme(theme))}.</span>
    </button>
  )
}
