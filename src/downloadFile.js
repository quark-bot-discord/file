import fetch from "node-fetch";
import { createGzip } from "zlib";
import { createCipheriv } from "crypto";

/**
 * Downloads a file from a URL and decrypts it
 * @param {String} url URL to download the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Promise<ReadableStream>}
 */
export default async function downloadFile(url, key, iv) {
  if (!url || !key || !iv) {
    throw new Error("Invalid parameters: url, key, and iv are required");
  }

  try {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Error when downloading file, got status ${res.status}`);
    }

    if (!res.body) {
      throw new Error("Response body is null");
    }

    const stream = res.body
      .on("error", (error) => {
        throw error;
      })
      .pipe(createGzip())
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
