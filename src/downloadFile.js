import fetch from "node-fetch";
import { constants, createGzip, createZstdCompress } from "zlib";
import { createCipheriv } from "crypto";
import https from "https";
import { checkCompressionFormat } from "./checkCompressionFormat";

/**
 * Downloads a file from a URL and decrypts it
 * @param {String} url URL to download the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Promise<ReadableStream>}
 */
export default async function downloadFile(url, key, iv, ip) {
  if (!url || !key || !iv) {
    throw new Error("Invalid parameters: url, key, and iv are required");
  }

  const agent = new https.Agent({ localAddress: ip });

  try {
    const res = await fetch(url, { agent });
    if (!res.ok) {
      throw new Error(`Error when downloading file, got status ${res.status}`);
    }

    if (!res.body) {
      throw new Error("Response body is null");
    }

    const compressionFormat = checkCompressionFormat(
      (new Date().getTime() / 1000) | 0
    );

    const stream = res.body
      .on("error", (error) => {
        throw error;
      })
      .pipe(
        compressionFormat === "zstd"
          ? createZstdCompress({
              params: {
                [constants.ZSTD_c_compressionLevel]: 10,
              },
            })
          : createGzip()
      )
      .on("error", (error) => {
        throw error;
      })
      .pipe(createCipheriv("aes-256-cbc", key, iv))
      .on("error", (error) => {
        throw error;
      });

    return stream;
  } catch (error) {
    throw new Error(`Failed to download and process file: ${error.message}`);
  }
}
