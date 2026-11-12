import { describe, expect, it } from 'vitest'
import { findTool, tools } from './registry'

describe('tool registry', () => {
  it('has the Trivy report viewer, ready, at /trivy', () => {
    const trivy = findTool('trivy')
    expect(trivy?.name).toBe('Trivy report viewer')
    expect(trivy?.status).toBe('ready')
    expect(trivy?.path).toBe('/trivy')
  })

  it('describes what the Trivy tool does in three steps', () => {
    const steps = findTool('trivy')?.steps ?? []
    expect(steps.map((step) => step.name)).toEqual(['Upload', 'Review', 'Fix'])
  })

  it('gives the Trivy tool its own preview component (its example lives with it, not on Home)', () => {
    const trivy = findTool('trivy')
    expect(trivy && 'preview' in trivy && typeof trivy.preview).toBe('function')
  })

  it('has unique ids and unique paths, each path one segment under /', () => {
    expect(new Set(tools.map((t) => t.id)).size).toBe(tools.length)
    expect(new Set(tools.map((t) => t.path)).size).toBe(tools.length)
    for (const tool of tools) expect(tool.path).toMatch(/^\/[a-z0-9-]+$/)
  })

  it('gives every ready tool a page and no soon tool one', () => {
    for (const tool of tools) {
      expect('page' in tool).toBe(tool.status === 'ready')
    }
  })
})
