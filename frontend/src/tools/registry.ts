import type { ComponentType } from 'react'
import { TrivyPage } from './trivy/TrivyPage'
import { TrivyPreview } from './trivy/TrivyPreview'

/** Names of the icons the Home page can draw (see home/ToolIcon.tsx). */
export type ToolIconName = 'shield'

type ToolBase = {
  /** Stable key, never shown. */
  id: string
  name: string
  /** About two lines on the card. */
  description: string
  /** Browser path, one segment: '/trivy'. */
  path: string
  icon: ToolIconName
  /** What the tool does, in the order a person does it (shown on its card). */
  steps?: { name: string; text: string }[]
  /** A small picture of the tool's results, shown on its card (the tool owns its content). */
  preview?: ComponentType
}

/** A ready tool has a page; a "soon" tool is only a greyed card on Home. */
export type Tool = ToolBase & ({ status: 'ready'; page: ComponentType } | { status: 'soon' })

/**
 * The one list of tools. Home and the router read only this, so a new tool is
 * one entry here plus its page component.
 */
export const tools: readonly Tool[] = [
  {
    id: 'trivy',
    name: 'Trivy report viewer',
    description:
      'Upload a Trivy scan report and see the findings by severity, with fixes and exploit data.',
    path: '/trivy',
    status: 'ready',
    icon: 'shield',
    steps: [
      { name: 'Upload', text: 'A Trivy JSON or text report. It is read on your computer and never saved.' },
      { name: 'Review', text: 'Findings by severity, with known exploited (CISA KEV) and exploit probability (EPSS).' },
      { name: 'Fix', text: 'Trivy’s fixed version and an upgrade command for each CVE, plus an optional AI explanation.' },
    ],
    preview: TrivyPreview,
    page: TrivyPage,
  },
]

export function findTool(id: string): Tool | undefined {
  return tools.find((tool) => tool.id === id)
}
