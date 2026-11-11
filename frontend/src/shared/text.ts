// Helpers that make report text safe and readable to show.

/** A file size for people: "512 bytes", "2 KB" or "1.5 MB" (no line break before the unit). */
export function formatFileSize(bytes: number): string {
  const nbsp = '\u00a0'
  if (bytes < 1024) return countText(bytes, 'byte')
  const kilobytes = Math.round(bytes / 1024)
  if (kilobytes < 1024) return `${kilobytes}${nbsp}KB` // rounded first, so never "1024 KB"
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(/\.0$/, '')}${nbsp}MB`
}

/** "1 package" or "2 packages"; give the plural when it is not word + "s" ("vulnerabilities"). */
export function countText(count: number, word: string, plural = `${word}s`): string {
  return `${count} ${count === 1 ? word : plural}`
}

// Control, format (invisible, direction-changing), line/paragraph separator
// and unassigned characters; Python's isprintable(), used on the backend,
// refuses these too. The u flag also matches characters above U+FFFF.
const HIDDEN_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cn}]/gu

/** Line breaks and tabs, which the backend keeps in the AI's text. */
export const KEEP_LINE_BREAKS = '\n\t'

/**
 * Report and AI text is untrusted: an invisible or right-to-left character
 * could make a package or version look like something else. Wrap such text
 * in this where it is shown: those characters appear as visible codes (a
 * backslash, "u" and the hex number), except those in `keep`. The data
 * itself stays exactly as Trivy wrote it, so filters, keys and /api/fix
 * use the real values.
 */
export function visibleText(text: string, keep = ''): string {
  return text.replace(HIDDEN_CHARACTERS, (char) => {
    if (keep.includes(char)) return char
    const code = char.codePointAt(0) ?? 0
    const hex = code.toString(16).toUpperCase()
    // Braces above U+FFFF, so "\u{E0041}" is not read as \uE004 plus "1".
    return code > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, '0')}`
  })
}

/** The link if it is a plain http(s) address, else null (no javascript: etc.). */
export function safeLink(url: string | null): string | null {
  if (url === null) return null
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null
  } catch {
    return null // not a valid absolute URL
  }
}

/**
 * The scan time in the reader's locale. Trivy writes up to 9 fractional
 * digits. The JavaScript date standard defines 3 (Chrome accepts more,
 * other browsers may not), so the rest is cut first.
 */
export function formatScanDate(value: string | null, locale?: string, timeZone?: string): string {
  if (value === null) return 'unknown'
  const date = new Date(value.replace(/(\.\d{3})\d+/, '$1'))
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(date)
}

/**
 * True if showing the text would change it (hidden or direction-changing
 * characters become visible codes). A command like that must not be copied: what
 * would be pasted differs from what is on the screen. Line breaks and tabs are fine.
 */
export function hasHiddenCharacters(text: string): boolean {
  return visibleText(text, KEEP_LINE_BREAKS) !== text
}
