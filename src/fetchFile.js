const { existsSync, createReadStream } = require("fs");
const { createDecipheriv } = require("crypto");
const { createGunzip } = require("zlib");
const hash = require("hash.js");

/**
 * Finds, decrypts and decompresses a file
 * @param {String} url URL of the file to find
 * @param {BigInt} guild_id ID of guild that the attachment belongs to
 * @param {BigInt} channel_id ID of the channel that the attachment was sent to
 * @param {BigInt} attachment_id ID of the attachment
 * @param {Number} file_size Size of the file, in bytes
 * @returns {Promise<Object>}
 */
function fetchFile(url, guild_id, channel_id, attachment_id, file_size) {
    return new Promise((resolve, reject) => {
        /* we know the URL of the file, so we can hash that to calculate the name of the file */
        const path = `${process.cwd()}/file/store/${hash.sha512().update(url).digest("hex")}.enc`;
        /* we should then check that the file exists */
        /* files are deleted after a period of time, or sometimes have not been downloaded */
        if (path && existsSync(path)) {
            /* here we can just do what we did before when downloading the file, but in reverse */
            /* first we'll create a stream, which reads the content of the file that we've found */
            const stream = createReadStream(path)
                /* now we can decrypt the file */
                /* the key and iv must be recalculated using the IDs connected with the file, similar to before */
                /* if we don't have the correct info, we cannot decrypt the file */
                .pipe(createDecipheriv("aes-256-cbc", hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}${file_size}`).digest("hex")}${url}`).digest("hex").slice(0, 32), hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}`).digest("hex")}${file_size}`).digest("hex").slice(0, 16)))
                /* next we can decompress the file */
                .pipe(createGunzip());
            /* we'll return the path of the file (so it can be deleted once we're done with it) */
            /* and we'll also return the read stream to the file, which is used to upload the file to the serverlog */
            return resolve({ path, stream });
        }
        else
            return reject(new Error("File does not exist"));
    });
}

module.exports = fetchFile;