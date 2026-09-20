/**
 * The bytes of an opened or dropped file as text.
 *
 * Most JSON is UTF-8, but Windows PowerShell 5.1 (`ConvertTo-Json | Out-File`)
 * and Notepad's "Unicode" save both write UTF-16 — which, read as UTF-8, is a
 * NUL between every two letters. The byte order mark says which UTF-16 it is;
 * without one, JSON gives itself away anyway, because it begins with an ASCII
 * character and so with a zero byte on one side of it. TextDecoder drops the
 * mark itself, as Blob.text() does for UTF-8.
 */

const NUL = String.fromCharCode(0);

/** Null when the bytes are not text: an image, an archive, a spreadsheet. */
export function decodeText(bytes: Uint8Array): string | null {
  const text = new TextDecoder(encodingOf(bytes)).decode(bytes);
  // A NUL near the start means binary data, not a text file with a typo.
  return text.slice(0, 4096).includes(NUL) ? null : text;
}

function encodingOf(bytes: Uint8Array): "utf-8" | "utf-16le" | "utf-16be" {
  const [first, second] = bytes;
  if (first === 0xff && second === 0xfe) return "utf-16le";
  if (first === 0xfe && second === 0xff) return "utf-16be";
  if (first === 0xef) return "utf-8";
  if (bytes.length >= 2 && first !== 0 && second === 0) return "utf-16le";
  if (bytes.length >= 2 && first === 0 && second !== 0) return "utf-16be";
  return "utf-8";
}
