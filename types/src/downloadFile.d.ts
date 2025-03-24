/**
 * Downloads a file from a URL and decrypts it
 * @param {String} url URL to download the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Promise<ReadableStream>}
 */
export default function downloadFile(url: string, key: string, iv: string, ip: any): Promise<ReadableStream>;
