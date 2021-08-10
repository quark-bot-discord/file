const { createWriteStream } = require("fs");
const fetch = require("node-fetch");
const checkMaxAttachmentSize = require("./checkMaxAttachmentSize");
const { createGzip } = require("zlib");
const { createCipheriv } = require("crypto");
const hash = require("hash.js");

/**
 * Downloads, compresses and encrypts a file
 * @param {String} url URL of the file to download
 * @param {BigInt} guild_id ID of guild that the attachment belongs to
 * @param {BigInt} channel_id ID of the channel that the attachment was sent to
 * @param {BigInt} attachment_id ID of the attachment
 * @param {Number} premium_tier Premium tier of the guild
 * @param {Number} file_size Size of the file to download, in bytes
 * @returns {Promise}
 */
function downloadFile(url, guild_id, channel_id, attachment_id, premium_tier, file_size) {
    return new Promise(async (resolve, reject) => {
        /* determines the maximum file size that all non-nitro users in this guild can upload */
        const maxFileSize = checkMaxAttachmentSize(premium_tier);
        /* if the maximum available file size is greater than the actual file size */
        /* then we don't even bother downloading the file, as it's useless */
        if (maxFileSize < file_size)
            return reject("File too big");
        /* now we can attempt to download the file */
        const res = await fetch(url);
        /* if there was an error with fetching the file, we can just return */
        /* this could be a result of a server error, or the file being deleted quicker than we are able to download it */
        /* at present, there is little point in attempting to re-download the file */
        if (!res.ok)
            return reject(`Error when downloading file, got status ${res.status}`);
        /* we now have a stream of the file */
        res.body
            .on("error", error => {
                return reject(error);
            })
            /* first we should compress this using gzip */
            .pipe(createGzip())
            .on("error", error => {
                return reject(error);
            })
            /* then we'll encrypt the file using aes-256-cbc */
            /* you can read up on AES encryption here: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard */
            /* and here: https://proprivacy.com/guides/aes-encryption */
            /* we generate a new key and iv for every file */
            /* this is done by hashing the IDs (very long numbers) provided by Discord, and trimming them down to the correct size */
            /* the idea is that it makes it impossible for the file to be decrypted unless you know the ID of the guild, channel and file, as well as the uncompressed size of the file */
            /* and if you do know the IDs for the file, then you'd have access to the file anyway, as you can simply visit the URL of the file hosted by Discord */
            .pipe(createCipheriv("aes-256-cbc", hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}${file_size}`).digest("hex")}${url}`).digest("hex").slice(0, 32), hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}`).digest("hex")}${file_size}`).digest("hex").slice(0, 16)))
            .on("error", error => {
                return reject(error);
            })
            /* we also hash the URL of the file to create the file name in order to mask any details about the file */
            /* the filename will look something like this: 5f3c36aa5f7c478cac84052271b18a78d064004af9a45f3d54005dfd1b8d11044c935a89590be7c8c7d1ce23a05c112f020d6857aa1880c776e5ea395e055a94.enc */
            /* the hash cannot be reversed, which means that you'd need to know the URL of the file if you wanted to access it */
            /* and similar to before, if you already know the URL of the file, you'd have access to this file anyway */
            .pipe(createWriteStream(`${process.cwd()}/file/store/${hash.sha512().update(url).digest("hex")}.enc`))
            .on("error", error => {
                return reject(error);
            })
            .on("close", () => {
                /* essentially, the security comes from the fact that in order to access this data, you need to know specific details about the data you want to access beforehand */
                /* and now we can just resolve the promise in order to indicate that everything went well */
                return resolve();
            });
    });
}

module.exports = downloadFile;