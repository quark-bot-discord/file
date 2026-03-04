import { createDecipheriv } from "crypto";
import { createZstdDecompress, createBrotliDecompress } from "zlib";
import { Transform } from "stream";

/**
 * Fetches a file from a stream, decrypts it, and decompresses it
 * Reads the first byte to determine compression type:
 * 0x01 = Brotli, 0x00 = None, unknown/legacy = Zstd fallback
 * @param {Stream} stream Stream to fetch the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Stream}
 */
export function fetchFile(stream: NodeJS.ReadableStream, key: string, iv: string): NodeJS.ReadableStream {
  const decrypted = stream.pipe(createDecipheriv("aes-256-cbc", key, iv));

  // Transform stream to read indicator byte and decompress with appropriate algorithm
  const decompressWithFallback = new Transform({
    transform(chunk: Buffer, encoding: string, callback: Function) {
      // @ts-ignore
      if (!this.decompressor) {
        // Read first byte to determine compression type
        if (chunk.length === 0) {
          callback();
          return;
        }

        const indicator = chunk[0];
        const dataWithoutIndicator = chunk.slice(1);

        // Select decompressor based on indicator byte
        let dataToWrite;
        if (indicator === 0x01) {
          // @ts-ignore
          this.decompressor = createBrotliDecompress();
          dataToWrite = dataWithoutIndicator;
        } else if (indicator === 0x00) {
          // no compression
          // @ts-ignore
          this.decompressor = new (require("stream").PassThrough)();
          dataToWrite = dataWithoutIndicator;
        } else {
          // Fallback to Zstd for unknown indicators
          // @ts-ignore
          this.decompressor = createZstdDecompress();
          dataToWrite = chunk; // Use data with the indicator for Zstd
        }

        // @ts-ignore
        this.decompressor.on("data", (data: Buffer) => {
          this.push(data);
        });

        // @ts-ignore
        this.decompressor.on("error", (error: Error) => {
          this.destroy(error);
        });

        // Write the data
        if (dataToWrite.length > 0) {
          // @ts-ignore
          this.decompressor.write(dataToWrite);
        }
      } else {
        // @ts-ignore
        this.decompressor.write(chunk);
      }
      callback();
    },

    flush(callback) {
      // @ts-ignore
      if (this.decompressor) {
        // @ts-ignore
        this.decompressor.end(callback);
      } else {
        callback();
      }
    },
  });

  return decrypted.pipe(decompressWithFallback);
}
