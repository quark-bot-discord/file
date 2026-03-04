/**
 * Downloads a file from a URL, compresses it with Brotli, and encrypts it
 * Prepends a single byte (0x01) to indicate Brotli compression
 * @param {String} url URL to download the file from
 * @param {String} key Key to encrypt the file with
 * @param {String} iv IV to encrypt the file with
 * @param {String} ip IP address to bind to (optional)
 * @returns {Promise<ReadableStream>}
 */
export declare function downloadFile(url: string, key: string, iv: string, ip?: string): Promise<NodeJS.ReadableStream>;
