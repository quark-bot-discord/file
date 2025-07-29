/**
 * Fetches a file from a stream and decrypts it
 * @param {Stream} stream Stream to fetch the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Stream}
 */
export default function fetchFile(stream: Stream, key: string, iv: string, compressionFormat: "gzip" | "zstd"): Stream;
