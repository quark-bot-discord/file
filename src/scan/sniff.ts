/**
 * True when the first bytes are a format the hasher can decode. The decision
 * is made on content, not on the file name or the content type the uploader
 * chose, so renaming an image does not skip the check.
 */
export function isHashableImage(head: Buffer): boolean {
  if (head.length < 12) return false;
  // JPEG
  if (head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return true;
  // PNG
  if (
    head.readUInt32BE(0) === 0x89504e47 &&
    head.readUInt32BE(4) === 0x0d0a1a0a
  )
    return true;
  const ascii = head.toString("latin1", 0, 12);
  if (ascii.startsWith("GIF87a") || ascii.startsWith("GIF89a")) return true;
  if (ascii.startsWith("RIFF") && ascii.slice(8, 12) === "WEBP") return true;
  // TIFF, little and big endian
  if (ascii.startsWith("II*\0") || ascii.startsWith("MM\0*")) return true;
  // AVIF
  if (ascii.slice(4, 8) === "ftyp" && /^avi[fs]$/.test(ascii.slice(8, 12)))
    return true;
  return false;
}

/** Bytes of the file needed before `isHashableImage` can answer. */
export const SNIFF_BYTES = 12;
