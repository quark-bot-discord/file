import hashjs from "hash.js";
const { sha512 } = hashjs;
import { PassThrough } from "stream";
import { Upload } from "@aws-sdk/lib-storage";
import {
  PutBucketLifecycleConfigurationCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import _downloadFile from "./src/downloadFile.js";
import _fetchFile from "./src/fetchFile.js";
import checkMaxAttachmentSize from "./src/checkMaxAttachmentSize.js";
import sortFiles from "./src/sortFiles.js";

const sleep = (period) =>
  new Promise((resolve, reject) => setTimeout(resolve, period));

export default class FileStorage {
  constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey }) {
    const s3Files = new S3Client({
      endpoint: s3Url,
      credentials: {
        accessKeyId: s3AccessKeyId,
        secretAccessKey: s3SecretAccessKey,
      },
      bucketEndpoint: true,
      region: "se-sto-1",
    });

    this.s3Url = s3Url;

    this.s3FileBucket = s3FileBucket;

    this.s3Files = s3Files;

    this.s3Files.send(
      new PutBucketLifecycleConfigurationCommand({
        Bucket: `${this.s3Url}${this.s3FileBucket}`,
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
      })
    );
  }

  uploadStream({ Bucket, Key }) {
    const pass = new PassThrough();
    return {
      writeStream: pass,
      promise: new Upload({
        client: new S3Client({
          endpoint: this.s3Url,
          region: "se-sto-1",
          credentials: this.s3Files.config.credentials,
        }),
        params: {
          Bucket,
          Key,
          Body: pass,
        },
      }).done(),
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

    const stream = await _downloadFile(url, encryptionKey, encryptionIv);

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
      raw = await this.s3Files.send(
        new GetObjectCommand({
          Bucket: `${this.s3Url}${this.s3FileBucket}`,
          Key: fileName,
        })
      );
    } catch (error) {
      if (error.statusCode == 404) {
        await sleep(10000);
        raw = await this.s3Files.send(
          new GetObjectCommand({
            Bucket: `${this.s3Url}${this.s3FileBucket}`,
            Key: fileName,
          })
        );
      } else throw error;

      return null;
    }

    return {
      stream: _fetchFile(raw.Body, encryptionKey, encryptionIv),
      size: raw.ContentLength,
      name: fileName,
    };
  }

  deleteFile(name) {
    return this.s3Files.send(
      new DeleteObjectCommand({
        Bucket: `${this.s3Url}${this.s3FileBucket}`,
        Key: name,
      })
    );
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
      await this.s3Files.send(
        new HeadObjectCommand({
          Bucket: `${this.s3Url}${this.s3FileBucket}`,
          Key: fileName,
        })
      );

      return true;
    } catch (error) {
      return false;
    }
  }
}
