const hash = require("hash.js");
const { PassThrough } = require('stream');
const AWS = require('aws-sdk');
const _downloadFile = require('./src/downloadFile');
const _fetchFile = require('./src/fetchFile');
const checkMaxAttachmentSize = require("./src/checkMaxAttachmentSize");

class FileStorage {
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey }) {

        const s3Files = new AWS.S3({
            endpoint: `${s3Url}${s3FileBucket}`,
            accessKeyId: s3AccessKeyId,
            secretAccessKey: s3SecretAccessKey,
            s3BucketEndpoint: true
        });

        this.s3FileBucket = s3FileBucket;

        this.s3Files = s3Files;

    }

    uploadStream({ Bucket, Key }) {
        const pass = new PassThrough();
        return {
            writeStream: pass,
            promise: this.s3Files.upload({ Bucket, Key, Body: pass }).promise(),
        };
    }

    checkMaxAttachmentSize(premium_tier) {

        return checkMaxAttachmentSize(premium_tier);

    }

    getEncryptionKeys(guild_id, channel_id, attachment_id, file_size) {

        return { key: hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}${file_size}`).digest("hex")}satoshiNakamoto`).digest("hex").slice(0, 32), iv: hash.sha512().update(`${hash.sha512().update(`${guild_id}${channel_id}${attachment_id}`).digest("hex")}${file_size}`).digest("hex").slice(0, 16) };

    }

    getFileName(attachment_id, channel_id, guild_id, quark_premium, key = null) {

        const stringToHash = `${attachment_id}/${channel_id}/${guild_id}`;

        return `${key != null ? `${key}_` : ''}${quark_premium == true ? '1' : '0'}_1_${hash.sha512().update(stringToHash).digest("hex")}.enc`;

    }

    async downloadFile(url, guild_id, channel_id, attachment_id, premium_tier, file_size, quark_premium, key = null) {

        const maxFileSize = this.checkMaxAttachmentSize(premium_tier);

        if (maxFileSize < file_size)
            return new Error("File too big");

        const fileName = this.getFileName(attachment_id, channel_id, guild_id, quark_premium, key);

        const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(guild_id, channel_id, attachment_id, file_size);

        const stream = await _downloadFile(url, encryptionKey, encryptionIv);

        const { writeStream, promise } = this.uploadStream({
            Bucket: this.s3FileBucket,
            Key: fileName
        });

        stream
            .pipe(writeStream);

        return promise;

    }

    async fetchFile(guild_id, channel_id, attachment_id, file_size, quark_premium, key = null) {

        const fileName = this.getFileName(attachment_id, channel_id, guild_id, quark_premium, key);

        const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(guild_id, channel_id, attachment_id, file_size);

        const raw = await this.s3Files.getObject({
            Bucket: this.s3FileBucket,
            Key: fileName
        }).promise();

        const bufferStream = new PassThrough();
        bufferStream.end(raw.Body);

        return _fetchFile(bufferStream, encryptionKey, encryptionIv);

    }


}

module.exports = FileStorage;