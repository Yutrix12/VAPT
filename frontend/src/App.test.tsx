import { renderToStaticMarkup } from 'react-dom/server'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { describe, expect, it } from 'vitest'
import { appRoutes } from './App'
import { APP_NAME } from './tools/usePageTitle'
import { HomePage } from './home/HomePage'
import { tools, type Tool } from './tools/registry'
import { BackToTools } from './tools/trivy/BackToTools'

const trivy = tools[0]!

/** Render the app at a path, optionally after one more navigation (a click on a link). */
async function renderAt(path: string, then?: string): Promise<string> {
  const router = createMemoryRouter(appRoutes, { initialEntries: [path] })
  if (then) await router.navigate(then)
  return renderToStaticMarkup(<RouterProvider router={router} />)
}

function homeWith(list: readonly Tool[]): string {
  const router = createMemoryRouter([{ path: '/', element: <HomePage tools={list} /> }])
  return renderToStaticMarkup(<RouterProvider router={router} />)
}

describe('Home cards come from the registry', () => {
  it('links a ready card to its path, as one link around the whole card', () => {
    const html = homeWith([trivy])
    expect(html).toContain(`href="${trivy.path}"`)
    expect(html).toMatch(/<a [^>]*class="tool-card"[^>]*>.*Trivy report viewer.*Open/s)
    expect(html).toContain('Upload a Trivy scan report and see the findings by severity, with fixes and exploit data.')
  })

  it('shows a soon card with a label and no link', () => {
    const soon: Tool = { id: 'later', name: 'Later tool', description: 'Not yet.', path: '/later', status: 'soon', icon: 'shield' }
    const html = homeWith([trivy, soon])
    expect(html).toContain('Later tool')
    expect(html).toContain('Coming soon')
    expect(html).not.toContain('href="/later"')
    expect(html).not.toContain('More tools will appear here')
  })

  it('adds a muted placeholder only while there is a single tool', () => {
    expect(homeWith([trivy])).toContain('More tools will appear here')
  })
})

describe('Home page', () => {
  it('is named Vulnerability Insight Platform, in the header and as the page headline', async () => {
    expect(APP_NAME).toBe('Vulnerability Insight Platform')
    const html = await renderAt('/')
    expect(html).toMatch(/<header[^>]*>\s*<a [^>]*href="\/"[^>]*>(<svg.*?<\/svg>)?\s*Vulnerability Insight Platform/s)
    expect(html).toMatch(/<h1[^>]*>Vulnerability Insight Platform<\/h1>/)
  })

  it('says nothing about Trivy on its own: that text lives in the Trivy card', async () => {
    const html = await renderAt('/')
    const heroEnd = html.indexOf('class="tools')
    expect(html.slice(0, heroEnd)).not.toMatch(/Trivy/)
    const card = html.slice(html.indexOf('class="tool-card"'))
    for (const step of ['Upload', 'Review', 'Fix']) expect(card).toContain(`>${step}<`)
    expect(html).not.toContain('Decide what to fix first')
  })

  it('states what holds for every tool: it runs on your computer and saves nothing', async () => {
    const hero = (await renderAt('/')).split('class="tools')[0]
    expect(hero).toContain('Runs on your computer')
    expect(hero).toContain('Nothing is saved')
  })

  it('shows an example finding on the Trivy card, labelled as an example, with the severity levels', async () => {
    const html = await renderAt('/')
    const card = html.slice(html.indexOf('class="tool-card"'))
    expect(card).toContain('Example')
    expect(card).toContain('CVE-2021-44228')
    for (const level of ['Critical', 'High', 'Medium', 'Low', 'Unknown']) expect(card).toContain(`>${level}<`)
    expect(card).toContain('Known exploited (CISA KEV)')
  })

  it('has an ambient background that screen readers skip, and moving parts that are only decoration', async () => {
    const html = await renderAt('/')
    expect(html).toMatch(/class="hero-backdrop"[^>]*aria-hidden="true"/)
    expect(html.match(/class="hero-blob/g)).toHaveLength(3)
    expect(html).toMatch(/<svg class="brand-mark hero-mark rise"[^>]*aria-hidden="true"/)
  })

  it('lists the tools in one row, with the placeholder beside the featured tool', async () => {
    const html = await renderAt('/')
    expect(html).toMatch(/<ul class="tool-row"/)
    expect(html).toMatch(/<li class="tool-featured">.*<\/li><li class="tool-slot"><div class="tool-card tool-card-soon tool-card-placeholder"/s)
  })

  it('has one way into the Trivy viewer (the card), not a second button with the same job', async () => {
    const html = await renderAt('/')
    expect(html.match(/href="\/trivy"/g)).toHaveLength(1)
  })

  it('has no em-dash or en-dash anywhere', async () => {
    expect(await renderAt('/')).not.toMatch(/[–—]/)
  })
})

describe('routes', () => {
  it('shows Home at /', async () => {
    const html = await renderAt('/')
    expect(html).toContain('Trivy report viewer')
    expect(html).toContain(`href="${trivy.path}"`)
    expect(html).not.toContain('No report yet')
  })

  it('shows the Trivy page at /trivy, with the All tools link and no loaded-report note', async () => {
    const html = await renderAt('/trivy')
    expect(html).toContain('No report yet')
    expect(html).toContain('All tools')
    expect(html).not.toContain('is not saved')
  })

  it('shows Page not found with a link home for an unknown path', async () => {
    const html = await renderAt('/nope')
    expect(html).toContain('Page not found')
    expect(html).toMatch(/<a [^>]*href="\/"[^>]*>[^<]*Home/)
  })

  it('goes back to Home from the Trivy page', async () => {
    const html = await renderAt('/trivy', '/')
    expect(html).not.toContain('No report yet')
    expect(html).toContain('Open')
  })

  it('has an All tools link to / on the Trivy page', async () => {
    expect(await renderAt('/trivy')).toMatch(/<a [^>]*href="\/"[^>]*>(<span[^>]*>[^<]*<\/span>)? All tools/)
  })

  it('has an app-name link to Home in the header of every page', async () => {
    for (const path of ['/', '/trivy', '/nope']) {
      expect(await renderAt(path)).toMatch(/<header[^>]*>\s*<a [^>]*href="\/"/)
    }
  })
})

describe('leaving the Trivy page', () => {
  it('names the loss only when a report is loaded', () => {
    const wrap = (loaded: boolean) => {
      const router = createMemoryRouter([{ path: '/', element: <BackToTools reportLoaded={loaded} /> }])
      return renderToStaticMarkup(<RouterProvider router={router} />)
    }
    expect(wrap(true)).toContain('not saved')
    expect(wrap(false)).not.toContain('not saved')
  })
})
