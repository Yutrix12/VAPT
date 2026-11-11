// Plain functions behind the results page (no React here), so they are easy
// to test.
import { countText } from './shared/text'

/** The sentence for vulnerabilities that no upgrade closes (page and fix summary). */
export function openAfterUpgradeText(count: number): string {
  const one = count === 1
  return (
    `${countText(count, 'vulnerability', 'vulnerabilities')} in this package ${one ? 'has' : 'have'} ` +
    `no fixed version yet and ${one ? 'stays' : 'stay'} open after any upgrade.`
  )
}
