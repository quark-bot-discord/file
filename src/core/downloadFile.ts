import fetch from "node-fetch";
import { createCipheriv } from "crypto";
import https from "https";
import { Transform } from "stream";
import { getFileType } from "../util/getFileType.js";
import { checkBestCompression } from "../util/checkBestCompression.js";
import { getCompressionIndicator } from "../util/getCompressionIndicator.js";
import { compressData } from "./compressData.js";

/**
 * Downloads a file from a URL, compresses it with Brotli, and encrypts it
 * Prepends a single byte (0x01) to indicate Brotli compression
 * @param {String} url URL to download the file from
 * @param {String} key Key to encrypt the file with
 * @param {String} iv IV to encrypt the file with
 * @param {String} ip IP address to bind to (optional)
 * @returns {Promise<ReadableStream>}
 */
export async function downloadFile(url: string, key: string, iv: string, ip?: string): Promise<NodeJS.ReadableStream> {
  if (!url || !key || !iv) {
    throw new Error("Invalid parameters: url, key, and iv are required");
  }

  const agent = ip ? new https.Agent({ localAddress: ip }) : undefined;

  try {
    const res = await fetch(url, agent ? { agent } : {});
    if (!res.ok) {
      throw new Error(`Error when downloading file, got status ${res.status}`);
    }

    if (!res.body) {
      throw new Error("Response body is null");
    }

    const mimeType = getFileType(url, res.headers.get("content-type"));
    const compression = checkBestCompression(mimeType);

    let headerWritten = false;
    const prependIndicator = new Transform({
      transform(chunk, encoding, callback) {
        if (!headerWritten) {
          this.push(getCompressionIndicator(compression));
          headerWritten = true;
        }
        this.push(chunk);
        callback();
      },
    });

    const stream = res.body
      .on("error", (error: Error) => {
        throw error;
      })
      .pipe(
        compressData(compression, res.headers.get("content-length") ? Number(res.headers.get("content-length")) : undefined)
      )
      .on("error", (error: Error) => {
        throw error;
      })
      .pipe(prependIndicator)
      .on("error", (error: Error) => {
        throw error;
      })
      .pipe(createCipheriv("aes-256-cbc", key, iv))
      .on("error", (error: Error) => {
        throw error;
      });

    return stream;
  } catch (error: unknown) {
    throw new Error(`Failed to download and process file: ${(<Error>error).message}`);
  }
}
