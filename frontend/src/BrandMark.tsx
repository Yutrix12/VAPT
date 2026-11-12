/**
 * The platform mark: the three severity shapes (diamond, triangle, circle) the app
 * uses next to every finding, in the current text colour. Decorative; the name beside it says the rest.
 */
export function BrandMark({ className = '' }: { className?: string }) {
  return (
    <svg className={`brand-mark ${className}`.trim()} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <path d="M8 3 14 9 8 15 2 9Z" />
      <path d="M24 3 30 15H18Z" />
      <circle cx="16" cy="24" r="6" />
    </svg>
  )
}
