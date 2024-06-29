const fetch = require("node-fetch");
const { createGzip } = require("zlib");
const { createCipheriv } = require("crypto");

/**
 * Downloads a file from a URL and decrypts it
 * @param {String} url URL to download the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Promise<Stream>}
 */
function _downloadFile(url, key, iv) {
    return new Promise(async (resolve, reject) => {
        const res = await fetch(url);
        if (!res.ok)
            return reject(`Error when downloading file, got status ${res.status}`);
        const stream = res.body
            .on("error", error => {
                return reject(error);
            })
            .pipe(createGzip())
            .on("error", error => {
                return reject(error);
            })
            .pipe(createCipheriv("aes-256-cbc", key, iv))
            .on("error", error => {
                return reject(error);
            });
        return resolve(stream);
    });
}

module.exports = _downloadFile;