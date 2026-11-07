import { afterEach, describe, expect, it, vi } from 'vitest'
import { analyzeReport } from './api'

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
      summary: { by_severity: {}, by_status: { [hidden]: 1 } },
      package_groups: [{ pkg_name: hidden, fixed_versions: [hidden] }],
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(body)))
    expect(await analyzeReport(new File(['{}'], 'report.json'))).toEqual({ ok: true, data: body })
  })

  it('returns the error detail unchanged', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ detail: hidden }, { status: 400 })))
    expect(await analyzeReport(new File(['{}'], 'report.json'))).toEqual({ ok: false, message: hidden })
  })
})
