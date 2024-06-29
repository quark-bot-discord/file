const { createDecipheriv } = require("crypto");
const { createGunzip } = require("zlib");

/**
 * Fetches a file from a stream and decrypts it
 * @param {Stream} stream Stream to fetch the file from
 * @param {String} key Key to decrypt the file with
 * @param {String} iv IV to decrypt the file with
 * @returns {Stream}
 */
function _fetchFile(stream, key, iv) {

    return stream
        .pipe(createDecipheriv("aes-256-cbc", key, iv))
        .pipe(createGunzip());

}

module.exports = _fetchFile;