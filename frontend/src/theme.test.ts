import { describe, expect, it } from 'vitest'
import { nextTheme, parseTheme, themeLabel } from './theme'

describe('theme choice', () => {
  it('cycles system, light, dark and back', () => {
    expect(nextTheme('system')).toBe('light')
    expect(nextTheme('light')).toBe('dark')
    expect(nextTheme('dark')).toBe('system')
  })

  it('reads a saved value and treats anything else as the system setting', () => {
    expect(parseTheme('light')).toBe('light')
    expect(parseTheme('dark')).toBe('dark')
    expect(parseTheme('system')).toBe('system')
    expect(parseTheme(null)).toBe('system')
    expect(parseTheme('purple')).toBe('system')
  })

  it('names each choice in words', () => {
    expect(themeLabel('system')).toBe('Auto')
    expect(themeLabel('light')).toBe('Light')
    expect(themeLabel('dark')).toBe('Dark')
  })
})
