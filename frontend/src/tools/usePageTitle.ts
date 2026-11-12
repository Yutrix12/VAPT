import { useEffect } from 'react'

/** The name of the app: one place for the tools that read vulnerability scans. */
export const APP_NAME = 'Vulnerability Insight Platform'

/** Set document.title for the page on screen: "Page · App name", or just the app name. */
export function usePageTitle(page?: string) {
  useEffect(() => {
    document.title = page ? `${page} · ${APP_NAME}` : APP_NAME
  }, [page])
}
