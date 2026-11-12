import { BrandMark } from '../BrandMark'
import type { ToolIconName } from '../tools/registry'

/** The glyph tile on a tool card; decorative, the tool name carries the meaning. */
export function ToolIcon({ name }: { name: ToolIconName }) {
  switch (name) {
    case 'shield':
      return (
        <span className="tool-glyph">
          <BrandMark />
        </span>
      )
  }
}
