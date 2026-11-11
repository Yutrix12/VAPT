import { afterEach, describe, expect, it, vi } from 'vitest'
import { analyzeReport, explainOther } from './client'

// Hidden characters are made visible only where text is shown. The data the
// page keeps (and sends back to /api/fix) must stay exactly as it arrived.
const hidden = 'openssl' + String.fromCodePoint(0x202e) + 'lmth'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('callBackend', () => {
  it('returns the data unchanged, hidden characters included', async () => {
    const body = {
      report: { file_name: hidden },
      summary: {
        by_severity: {},
        by_status: { [hidden]: 1 },
        by_kind: { vulnerability: 0, misconfiguration: 0, secret: 0, license: 0 },
      },
      package_groups: [{ pkg_name: hidden, fixed_versions: [hidden] }],
      misconfigurations: [],
      secrets: [],
      licenses: [],
      secret_fix_steps: [],
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(body)))
    expect(await analyzeReport(new File(['{}'], 'report.json'))).toEqual({ ok: true, data: body })
  })

  it('returns the error detail unchanged', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ detail: hidden }, { status: 400 })))
    expect(await analyzeReport(new File(['{}'], 'report.json'))).toEqual({ ok: false, message: hidden })
  })
})

describe('explainOther', () => {
  it('posts the finding to /api/fix/other and returns the advice', async () => {
    const advice = {
      kind: 'secret', status: 'solution_options', summary: 's', solutions: ['a'], mitigations: [],
      risk_notes: 'r', disclaimer: 'd',
    }
    const fetchMock = vi.fn(async () => Response.json(advice))
    vi.stubGlobal('fetch', fetchMock)
    const request = { kind: 'secret', rule_id: 'x', category: null, severity: 'HIGH', title: null, target: 't', start_line: 1, end_line: 1 } as const
    expect(await explainOther(request)).toEqual({ ok: true, data: advice })
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/fix/other')
    expect(JSON.parse(init.body as string)).toEqual(request)
  })

  it('refuses an answer that is not the advice for another kind', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ kind: 'vulnerability' })))
    const result = await explainOther({ kind: 'license', name: null, category: null, license_class: null, package: null, severity: 'LOW' })
    expect(result.ok).toBe(false)
  })
})
