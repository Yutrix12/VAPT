// Saving a text the page built as a file (no server involved).

/** Offer `text` as a download named `fileName`. */
export function downloadText(fileName: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.append(link)
  link.click()
  link.remove()
  // Some browsers start reading the file only after click() returns, so
  // the URL is released a moment later.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
