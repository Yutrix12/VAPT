// The colour theme choice: follow the system, or force light or dark (no React here).
export type Theme = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'theme'

export function nextTheme(theme: Theme): Theme {
  return theme === 'system' ? 'light' : theme === 'light' ? 'dark' : 'system'
}

export function parseTheme(value: string | null): Theme {
  return value === 'light' || value === 'dark' ? value : 'system'
}

export function themeLabel(theme: Theme): string {
  return theme === 'system' ? 'Auto' : theme === 'light' ? 'Light' : 'Dark'
}

/** Put the choice on <html>: "system" removes it, so the system setting decides. */
export function applyTheme(theme: Theme): void {
  if (theme === 'system') delete document.documentElement.dataset.theme
  else document.documentElement.dataset.theme = theme
}

/** The saved choice (only "light", "dark" or nothing is stored; no report data ever is). */
export function loadTheme(): Theme {
  try {
    return parseTheme(localStorage.getItem(STORAGE_KEY))
  } catch {
    return 'system' // storage can be blocked
  }
}

export function saveTheme(theme: Theme): void {
  try {
    if (theme === 'system') localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // The choice then lasts only until the page is closed.
  }
}
