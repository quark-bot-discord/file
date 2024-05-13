const { existsSync, createReadStream } = require("fs");
const { createDecipheriv } = require("crypto");
const { createGunzip } = require("zlib");
const hash = require("hash.js");

const sleep = period => new Promise((resolve, reject) => setTimeout(resolve, period));

/**
 * Finds, decrypts and decompresses a file
 * @param {String} url URL of the file to find
 * @param {BigInt} guild_id ID of guild that the attachment belongs to
 * @param {BigInt} channel_id ID of the channel that the attachment was sent to
 * @param {BigInt} attachment_id ID of the attachment
 * @param {Number} file_size Size of the file, in bytes
 * @param {Boolean} quark_premium Whether this guild has Quark premium
 * @returns {Promise<Object>}
 */
function fetchFile(url, guild_id, channel_id, attachment_id, file_size, quark_premium, key = null) {
    return new Promise(async (resolve, reject) => {
        const stringToHash = `${attachment_id}/${channel_id}/${guild_id}`;
        /* we know the data about the file, so we can hash that to calculate the name of the file */
        const path0 = `${process.cwd()}/file/store/${key != null ? `${key}_` : ''}${quark_premium == true ? '1' : '0'}_0_${hash.sha512().update(stringToHash).digest("hex")}.enc`;
        const path1 = `${process.cwd()}/file/store/${key != null ? `${key}_` : ''}${quark_premium == true ? '1' : '0'}_1_${hash.sha512().update(stringToHash).digest("hex")}.enc`;
        /* check if the file has fully downloaded or not yet */
        /* if the file has not yet been downloaded, we should wait for 10 seconds before resuming */
        if (path0 && existsSync(path0))
            await sleep(10000);
        /* we should then check that the file exists */
        /* files are deleted after a period of time, or sometimes have not been downloaded */
        if (path1 && existsSync(path1)) {
            /* here we can just do what we did before when downloading the file, but in reverse */
            /* first we'll create a stream, which reads the content of the file that we've found */
            try {
                const stream = createReadStream(path1)
                    /* now we can decrypt the file */
                    /* the key and iv must be recalculated using the IDs connected with the file, similar to before */
                    /* if we don't have the correct info, we cannot decrypt the file */
                    .pipe(createDecipheriv("aes-256-cbc", hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}${file_size}`).digest("hex")}satoshiNakamoto`).digest("hex").slice(0, 32), hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}`).digest("hex")}${file_size}`).digest("hex").slice(0, 16)))
                    /* next we can decompress the file */
                    .pipe(createGunzip());
                /* we'll return the path of the file (so it can be deleted once we're done with it) */
                /* and we'll also return the read stream to the file, which is used to upload the file to the serverlog */
                return resolve({ path: path1, stream });
            } catch (_) {
                /* if we encounter an error here, it's usually down to some issue with the decryption */
                /* we should catch the error so it doesn't crash everything */
                /* the fact that i've not been able to replicate this issue for over a year, nor has anyone reported it, shows how minor it is */
                /* so should be fine just to let it fail */
                return reject();
            }
        }
        else
            return reject(new Error("File does not exist"));
    });
}

module.exports = fetchFile;