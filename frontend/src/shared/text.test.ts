import { describe, expect, it } from 'vitest'
import {
  countText,
  formatScanDate,
  formatFileSize,
  hasHiddenCharacters,
  KEEP_LINE_BREAKS,
  safeLink,
  visibleText,
} from './text'

describe('hasHiddenCharacters', () => {
  it('is true when what is shown would differ from the text itself', () => {
    expect(hasHiddenCharacters('apt-get install openssl‮')).toBe(true)
    expect(hasHiddenCharacters('pip install ​pkg')).toBe(true)
    expect(hasHiddenCharacters('echo\u001b[31m')).toBe(true)
  })

  it('is false for plain commands, with line breaks and tabs', () => {
    expect(hasHiddenCharacters('apt-get update\napt-get install --only-upgrade openssl=1:3.0')).toBe(false)
    expect(hasHiddenCharacters('a\tb')).toBe(false)
    expect(hasHiddenCharacters('')).toBe(false)
  })
})

describe('visibleText', () => {
  it('makes invisible and direction-changing characters visible', () => {
    expect(visibleText('openssl\u202Elmth.exe')).toBe('openssl\\u202Elmth.exe')
    expect(visibleText('3.5.4\u200B')).toBe('3.5.4\\u200B')
    expect(visibleText('a\u001b[31mb')).toBe('a\\u001B[31mb')
  })

  it('also catches other invisible characters, above U+FFFF too', () => {
    const arabicMark = String.fromCodePoint(0x061c)
    const softHyphen = String.fromCodePoint(0x00ad)
    const tagA = String.fromCodePoint(0xe0041)
    expect(visibleText(`a${arabicMark}b${softHyphen}c${tagA}1`)).toBe('a\\u061Cb\\u00ADc\\u{E0041}1')
  })

  it('keeps line breaks and tabs only when asked (AI text)', () => {
    expect(visibleText('a\nb\tc', KEEP_LINE_BREAKS)).toBe('a\nb\tc')
    expect(visibleText('a\nb')).toBe('a\\u000Ab')
  })

  it('leaves ordinary text exactly as it is', () => {
    expect(visibleText('libssl3t64 3.5.7-1~deb13u3: Ünïcode, 日本')).toBe('libssl3t64 3.5.7-1~deb13u3: Ünïcode, 日本')
  })
})

describe('safeLink', () => {
  it('allows http and https links only', () => {
    expect(safeLink('https://avd.aquasec.com/nvd/cve-2026-1')).toBe(
      'https://avd.aquasec.com/nvd/cve-2026-1')
    expect(safeLink('javascript:alert(1)')).toBeNull()
    expect(safeLink('data:text/html,<b>x</b>')).toBeNull()
    expect(safeLink('not a url')).toBeNull()
    expect(safeLink(null)).toBeNull()
  })
})

describe('countText', () => {
  it('uses the singular only for exactly one', () => {
    expect(countText(1, 'package')).toBe('1 package')
    expect(countText(0, 'package')).toBe('0 packages')
    expect(countText(54, 'package')).toBe('54 packages')
  })

  it('takes an irregular plural', () => {
    expect(countText(1, 'vulnerability', 'vulnerabilities')).toBe('1 vulnerability')
    expect(countText(2, 'vulnerability', 'vulnerabilities')).toBe('2 vulnerabilities')
  })
})

describe('formatScanDate', () => {
  it('formats an ISO date and keeps anything else as it was', () => {
    expect(formatScanDate('2026-11-06T09:45:32.7294274+05:30', 'en-GB', 'UTC'))
      .toBe('6 Nov 2026, 04:15')
    expect(formatScanDate('not a date', 'en-GB', 'UTC')).toBe('not a date')
    expect(formatScanDate(null, 'en-GB', 'UTC')).toBe('unknown')
  })
})

describe('formatFileSize', () => {
  it('uses bytes, KB or MB, whichever reads best', () => {
    expect(formatFileSize(512)).toBe('512 bytes')
    expect(formatFileSize(1)).toBe('1 byte')
    expect(formatFileSize(2048)).toBe('2\u00a0KB')
    expect(formatFileSize(1_572_864)).toBe('1.5\u00a0MB')
    expect(formatFileSize(1_048_400)).toBe('1\u00a0MB') // just under 1 MiB: not "1024 KB"
  })
})
