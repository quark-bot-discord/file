import { createDecipheriv } from "crypto";
import { createGunzip, createZstdDecompress } from "zlib";

/**
 * Fetches a file from a stream and decrypts it
 * @param {Stream} stream Stream to fetch the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Stream}
 */
export default function fetchFile(stream, key, iv, compressionFormat = "zstd") {
  return stream
    .pipe(createDecipheriv("aes-256-cbc", key, iv))
    .pipe(
      compressionFormat === "zstd" ? createZstdDecompress() : createGunzip()
    );
}
