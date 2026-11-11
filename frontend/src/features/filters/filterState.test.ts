import { describe, expect, it } from 'vitest'
import { SEVERITIES } from '../../api/types'
import { ALL_KINDS, defaultFilters, isFiltering } from './filterState'

describe('filter state', () => {
  it('starts with nothing filtered', () => {
    const filters = defaultFilters()
    expect(filters).toEqual({ search: '', kind: ALL_KINDS, severities: new Set(SEVERITIES), status: '', fixOnly: false })
    expect(isFiltering(filters)).toBe(false)
  })

  it('is filtering as soon as one filter is on', () => {
    const base = defaultFilters()
    expect(isFiltering({ ...base, search: 'ssl' })).toBe(true)
    expect(isFiltering({ ...base, search: '   ' })).toBe(false) // blank text filters nothing
    expect(isFiltering({ ...base, kind: 'secret' })).toBe(true)
    expect(isFiltering({ ...base, status: 'fixed' })).toBe(true)
    expect(isFiltering({ ...base, fixOnly: true })).toBe(true)
    expect(isFiltering({ ...base, severities: new Set(['HIGH']) })).toBe(true)
  })

  it('returns a new state each time, so one reset never changes another', () => {
    expect(defaultFilters().severities).not.toBe(defaultFilters().severities)
  })
})
