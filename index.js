import { sha512 } from "hash.js";
import { PassThrough } from "stream";
import { S3 } from "aws-sdk";
import downloadFile from "./src/downloadFile.js";
import fetchFile from "./src/fetchFile.js";
import checkMaxAttachmentSize from "./src/checkMaxAttachmentSize.js";
import sortFiles from "./src/sortFiles.js";

const sleep = (period) =>
  new Promise((resolve, reject) => setTimeout(resolve, period));

export default class FileStorage {
  constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey }) {
    const s3Files = new S3({
      endpoint: `${s3Url}${s3FileBucket}`,
      accessKeyId: s3AccessKeyId,
      secretAccessKey: s3SecretAccessKey,
      s3BucketEndpoint: true,
    });

    this.s3FileBucket = s3FileBucket;

    this.s3Files = s3Files;

    this.s3Files.putBucketLifecycleConfiguration(
      {
        Bucket: s3FileBucket,
        LifecycleConfiguration: {
          Rules: [
            {
              Expiration: {
                Days: 30,
              },
              Status: "Enabled",
              Filter: {
                Prefix: "",
              },
              ID: "DeleteOldFiles",
            },
            {
              Expiration: {
                Days: 1,
              },
              Status: "Enabled",
              Filter: {
                Prefix: "0_",
              },
              ID: "DeleteStandardFiles",
            },
          ],
        },
      },
      (err, data) => {
        if (err) console.log(err);
      }
    );
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

  sortFiles(files, maxSize) {
    return sortFiles(files, maxSize);
  }

  getEncryptionKeys(guild_id, channel_id, attachment_id, file_size) {
    return {
      key: sha512()
        .update(
          `${sha512()
            .update(
              `${String(guild_id)}${String(channel_id)}${String(
                attachment_id
              )}${String(file_size)}`
            )
            .digest("hex")}satoshiNakamoto`
        )
        .digest("hex")
        .slice(0, 32),
      iv: sha512()
        .update(
          `${sha512()
            .update(
              `${String(guild_id)}${String(channel_id)}${String(attachment_id)}`
            )
            .digest("hex")}${String(file_size)}`
        )
        .digest("hex")
        .slice(0, 16),
    };
  }

  getFileName(attachment_id, channel_id, guild_id, quark_premium, key = null) {
    const stringToHash = `${attachment_id}/${channel_id}/${guild_id}`;

    return `${key != null ? `${key}_` : ""}${
      quark_premium == true ? "1" : "0"
    }_${sha512().update(stringToHash).digest("hex")}.enc`;
  }

  async downloadFile(
    url,
    guild_id,
    channel_id,
    attachment_id,
    premium_tier,
    file_size,
    quark_premium,
    key = null
  ) {
    const maxFileSize = this.checkMaxAttachmentSize(premium_tier);

    if (maxFileSize < file_size) throw new Error("File too big");

    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key
    );

    const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(
      guild_id,
      channel_id,
      attachment_id,
      file_size
    );

    const stream = await downloadFile(url, encryptionKey, encryptionIv);

    const { writeStream, promise } = this.uploadStream({
      Bucket: this.s3FileBucket,
      Key: fileName,
    });

    stream.pipe(writeStream);

    return promise;
  }

  async fetchFile(
    guild_id,
    channel_id,
    attachment_id,
    file_size,
    quark_premium,
    key = null
  ) {
    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key
    );

    const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(
      guild_id,
      channel_id,
      attachment_id,
      file_size
    );

    let raw;

    try {
      raw = await this.s3Files
        .getObject({
          Bucket: this.s3FileBucket,
          Key: fileName,
        })
        .promise();
    } catch (error) {
      if (error.statusCode == 404) {
        await sleep(10000);
        raw = await this.s3Files
          .getObject({
            Bucket: this.s3FileBucket,
            Key: fileName,
          })
          .promise();
      } else throw error;

      return null;
    }

    const bufferStream = new PassThrough();
    bufferStream.end(raw.Body);

    return {
      stream: fetchFile(bufferStream, encryptionKey, encryptionIv),
      size: raw.ContentLength,
      name: fileName,
    };
  }

  deleteFile(name) {
    return this.s3Files
      .deleteObject({
        Bucket: this.s3FileBucket,
        Key: name,
      })
      .promise();
  }

  async checkFileExists(
    attachment_id,
    channel_id,
    guild_id,
    quark_premium,
    key = null
  ) {
    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key
    );

    try {
      await this.s3Files
        .headObject({
          Bucket: this.s3FileBucket,
          Key: fileName,
        })
        .promise();

      return true;
    } catch (error) {
      return false;
    }
  }
}
