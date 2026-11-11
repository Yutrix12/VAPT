import { describe, expect, it } from 'vitest'
import { checkFileBeforeUpload } from './uploadLogic'

const MB = 1024 * 1024

describe('checkFileBeforeUpload', () => {
  it('accepts any file name up to 50 MB: the backend detects the format from the content', () => {
    expect(checkFileBeforeUpload('image.json', 3 * MB)).toBeNull()
    expect(checkFileBeforeUpload('REPORT.JSON', 50 * MB)).toBeNull()
    expect(checkFileBeforeUpload('report.txt', 10)).toBeNull()
    expect(checkFileBeforeUpload('report.html', 10)).toBeNull()
  })

  it('refuses files over 50 MB before uploading', () => {
    expect(checkFileBeforeUpload('big.json', 50 * MB + 1)).toBe(
      'Skipped big.json: the file is larger than 50 MB')
  })
})
