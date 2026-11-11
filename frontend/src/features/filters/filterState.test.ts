import { describe, expect, it } from 'vitest'
import { SEVERITIES } from '../../api/types'
import { ALL_KINDS, defaultFilters, isFiltering, statusApplies, withKind } from './filterState'

describe('filter state', () => {
  it('starts with nothing filtered', () => {
    const filters = defaultFilters()
    expect(filters).toEqual({ search: '', kind: ALL_KINDS, severities: new Set(SEVERITIES), status: '', fixOnly: false, kevOnly: false, sort: 'severity' })
    expect(isFiltering(filters)).toBe(false)
  })

  it('is filtering as soon as one filter is on', () => {
    const base = defaultFilters()
    expect(isFiltering({ ...base, search: 'ssl' })).toBe(true)
    expect(isFiltering({ ...base, search: '   ' })).toBe(false) // blank text filters nothing
    expect(isFiltering({ ...base, kind: 'secret' })).toBe(true)
    expect(isFiltering({ ...base, status: 'fixed' })).toBe(true)
    expect(isFiltering({ ...base, fixOnly: true })).toBe(true)
    expect(isFiltering({ ...base, kevOnly: true })).toBe(true)
    expect(isFiltering({ ...base, sort: 'kev' })).toBe(true) // so "Clear all" brings the default order back
    expect(isFiltering({ ...base, severities: new Set(['HIGH']) })).toBe(true)
  })

  it('returns a new state each time, so one reset never changes another', () => {
    expect(defaultFilters().severities).not.toBe(defaultFilters().severities)
  })
})

describe('the kind filter and the status filter', () => {
  it('says that a status applies to all kinds and to vulnerabilities only', () => {
    expect(statusApplies(ALL_KINDS)).toBe(true)
    expect(statusApplies('vulnerability')).toBe(true)
    expect(statusApplies('secret')).toBe(false)
  })

  it('clears the status when the new kind has none, so no hidden filter stays', () => {
    const fixed = { ...defaultFilters(), status: 'fixed' }
    expect(withKind(fixed, 'secret')).toMatchObject({ kind: 'secret', status: '' })
    expect(withKind(fixed, 'license').status).toBe('')
  })

  it('keeps the status for a kind that has one', () => {
    const fixed = { ...defaultFilters(), status: 'fixed' }
    expect(withKind(fixed, 'vulnerability').status).toBe('fixed')
    expect(withKind(fixed, ALL_KINDS).status).toBe('fixed')
  })
})
