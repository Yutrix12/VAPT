// What identifies one package group.
import { type PackageGroup } from '../../api/types'

/** A unique key per group: JSON keeps null and "" apart, and needs no separator. */
export function groupKey(group: PackageGroup): string {
  return JSON.stringify([group.target, group.pkg_name, group.installed_version])
}
