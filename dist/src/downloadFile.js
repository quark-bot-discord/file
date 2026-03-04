import fetch from "node-fetch";
import { constants, createBrotliCompress } from "zlib";
import { createCipheriv } from "crypto";
import https from "https";
import { Transform } from "stream";
import { getFileType } from "./getFileType";
import { checkBestCompression } from "./checkBestCompression";
import { getCompressionIndicator } from "./getCompressionIndicator";
import { compressData } from "./compressData";
/**
 * Downloads a file from a URL, compresses it with Brotli, and encrypts it
 * Prepends a single byte (0x01) to indicate Brotli compression
 * @param {String} url URL to download the file from
 * @param {String} key Key to encrypt the file with
 * @param {String} iv IV to encrypt the file with
 * @param {String} ip IP address to bind to (optional)
 * @returns {Promise<ReadableStream>}
 */
export default async function downloadFile(url, key, iv, ip) {
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
        const prependIndicator = new Transform({
            transform(chunk, encoding, callback) {
                if (!this.headerWritten) {
                    this.push(getCompressionIndicator(compression));
                    this.headerWritten = true;
                }
                this.push(chunk);
                callback();
            },
        });
        const stream = res.body
            .on("error", (error) => {
            throw error;
        })
            .pipe(compressData(compression, res.headers.get("content-length") ? Number(res.headers.get("content-length")) : undefined))
            .on("error", (error) => {
            throw error;
        })
            .pipe(prependIndicator)
            .on("error", (error) => {
            throw error;
        })
            .pipe(createCipheriv("aes-256-cbc", key, iv))
            .on("error", (error) => {
            throw error;
        });
        return stream;
    }
    catch (error) {
        throw new Error(`Failed to download and process file: ${error.message}`);
    }
}
//# sourceMappingURL=downloadFile.js.map