/**
 * Fetches a file from a stream, decrypts it, and decompresses it
 * Reads the first byte to determine compression type:
 * 0x01 = Brotli, 0x00 (or unknown) = Zstd fallback
 * @param {Stream} stream Stream to fetch the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Stream}
 */
export default function fetchFile(stream: Stream, key: string, iv: string): Stream;
