// What is checked before a report is uploaded.

export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024

/**
 * A reason to refuse the file before uploading it, or null if it is fine.
 * Only the size is checked here: the backend detects the format from the
 * content, never from the file name (U3).
 */
export function checkFileBeforeUpload(name: string, size: number): string | null {
  if (size > MAX_UPLOAD_BYTES) {
    return `Skipped ${name}: the file is larger than 50 MB`
  }
  return null
}
