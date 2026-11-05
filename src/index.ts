import hashjs from "hash.js";
const { sha512 } = hashjs;
import { createHmac } from "crypto";
import { PassThrough } from "stream";
import { Upload } from "@aws-sdk/lib-storage";
import {
  PutBucketLifecycleConfigurationCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  S3Client,
  NoSuchKey,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3";
import { downloadFile as _downloadFile } from "./core/downloadFile.js";
import { fetchFile as _fetchFile } from "./core/fetchFile.js";
import { checkMaxAttachmentSize } from "./util/checkMaxAttachmentSize.js";
import { sortFiles } from "./util/sortFiles.js";
import https from "https";
import { NodeHttpHandler } from "@smithy/node-http-handler";
const httpsAgent = new https.Agent({
  maxSockets: 512,
});

/**
 * Resolve once the stream has produced its first chunk (or ended empty);
 * reject if it errors first. Nothing is consumed — `readable` only says data
 * is buffered — so the caller can pipe it afterwards as before.
 */
function primeStream(stream: NodeJS.ReadableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    const done = (err?: Error) => {
      stream.removeListener("readable", onReadable);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
      if (err) reject(err);
      else resolve();
    };
    const onReadable = () => done();
    const onEnd = () => done();
    const onError = (err: Error) => done(err);
    stream.once("readable", onReadable);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

const sleep = (period: number) =>
  new Promise((resolve, reject) => setTimeout(resolve, period));

export {
  checkMaxAttachmentSize,
  sortFiles,
  NoSuchKey,
  _fetchFile,
  _downloadFile,
};

/**
 * S3 user-metadata key recording which key derivation an object was written
 * with. Absent means 1.
 */
const KEY_VERSION_METADATA = "kv";

export default class FileStorage {
  downloadIp?: string;
  encryptionSecret?: string;
  s3Url: string;
  s3Region: string;
  s3FileBucket: string;
  s3Files: S3Client;

  constructor({
    s3Url,
    s3FileBucket,
    s3AccessKeyId,
    s3SecretAccessKey,
    s3Region,
    fileExpirationDaysStandard,
    fileExpirationDaysExtended,
    fileExpirationDaysUltraExtended,
    downloadIp,
    encryptionSecret,
  }: {
    s3Url: string;
    s3FileBucket: string;
    s3AccessKeyId: string;
    s3SecretAccessKey: string;
    s3Region: string;
    fileExpirationDaysStandard?: number;
    fileExpirationDaysExtended?: number;
    fileExpirationDaysUltraExtended?: number;
    downloadIp?: string;
    /**
     * Secret mixed into the key for message attachments. Falls back to the
     * FILE_ENCRYPTION_SECRET env var, so a consumer opts in by setting that
     * and nothing else. Unset: behaviour is unchanged.
     */
    encryptionSecret?: string;
  }) {
    this.downloadIp = downloadIp;

    this.encryptionSecret =
      encryptionSecret || process.env.FILE_ENCRYPTION_SECRET || undefined;

    const s3Files = new S3Client({
      endpoint: s3Url,
      credentials: {
        accessKeyId: s3AccessKeyId,
        secretAccessKey: s3SecretAccessKey,
      },
      bucketEndpoint: true,
      region: s3Region,
      requestHandler: new NodeHttpHandler({
        requestTimeout: 30000,
        httpsAgent,
      }),
    });

    this.s3Url = s3Url;

    this.s3Region = s3Region;

    this.s3FileBucket = s3FileBucket;

    this.s3Files = s3Files;

    this.s3Files.send(
      new PutBucketLifecycleConfigurationCommand({
        Bucket: `${this.s3Url}${this.s3FileBucket}`,
        LifecycleConfiguration: {
          Rules: [
            {
              Expiration: {
                Days: fileExpirationDaysExtended,
              },
              Status: "Enabled",
              Filter: {
                Prefix: "",
              },
              ID: "DeleteOldFiles",
            },
            {
              Expiration: {
                Days: fileExpirationDaysStandard,
              },
              Status: "Enabled",
              Filter: {
                Prefix: "0_",
              },
              ID: "DeleteStandardFiles",
            },
            {
              Expiration: {
                Days: fileExpirationDaysUltraExtended,
              },
              Status: "Enabled",
              Filter: {
                Prefix: "2_",
              },
              ID: "DeleteUltraExtendedFiles",
            },
          ],
        },
      }),
    );
  }

  uploadStream({
    Bucket,
    Key,
    Metadata,
  }: {
    Bucket: string;
    Key: string;
    Metadata?: Record<string, string>;
  }) {
    const pass = new PassThrough();
    return {
      writeStream: pass,
      promise: new Upload({
        client: new S3Client({
          endpoint: this.s3Url,
          region: this.s3Region,
          credentials: this.s3Files.config.credentials,
        }),
        params: {
          Bucket,
          Key,
          Body: pass,
          Metadata,
        },
      }).done(),
    };
  }

  checkMaxAttachmentSize(premium_tier: number) {
    return checkMaxAttachmentSize(premium_tier);
  }

  sortFiles(files: any[], maxSize: number) {
    return sortFiles(files, maxSize);
  }

  /**
   * Version 1 derives the key from the ids, the size and a constant, all of
   * which are known to anyone who could see the message, so it only protects
   * against someone who has the stored objects and nothing else.
   *
   * Version 2 keys the derivation with `encryptionSecret`: the stored objects
   * are unreadable without a secret that never sits in the bucket.
   */
  getEncryptionKeys(
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    file_size: number,
    version: 1 | 2 = 1,
  ) {
    if (version === 2) {
      if (!this.encryptionSecret) {
        throw new Error(
          "File was encrypted with a secret this process does not have (FILE_ENCRYPTION_SECRET)",
        );
      }
      const ids = `${String(guild_id)}:${String(channel_id)}:${String(
        attachment_id,
      )}:${String(file_size)}`;
      const derive = (label: string) =>
        createHmac("sha512", this.encryptionSecret as string)
          .update(`${label}:${ids}`)
          .digest("hex");
      return {
        key: derive("key").slice(0, 32),
        iv: derive("iv").slice(0, 16),
      };
    }
    return {
      key: sha512()
        .update(
          `${sha512()
            .update(
              `${String(guild_id)}${String(channel_id)}${String(
                attachment_id,
              )}${String(file_size)}`,
            )
            .digest("hex")}satoshiNakamoto`,
        )
        .digest("hex")
        .slice(0, 32),
      iv: sha512()
        .update(
          `${sha512()
            .update(
              `${String(guild_id)}${String(channel_id)}${String(attachment_id)}`,
            )
            .digest("hex")}${String(file_size)}`,
        )
        .digest("hex")
        .slice(0, 16),
    };
  }

  getFileName(
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key = null,
    extendedExpiration = false,
  ) {
    const stringToHash = `${attachment_id}/${channel_id}/${guild_id}`;

    return `${extendedExpiration ? "2_" : ""}${key != null ? `${key}_` : ""}${
      quark_premium == true ? "1" : "0"
    }_${sha512().update(stringToHash).digest("hex")}.enc`;
  }

  async downloadFile(
    url: string,
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    premium_tier: number,
    file_size: number,
    quark_premium: boolean,
    key = null,
    extendedExpiration = false,
  ) {
    const maxFileSize = this.checkMaxAttachmentSize(premium_tier);

    if (maxFileSize < file_size) throw new Error("File too big");

    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key,
      extendedExpiration,
    );

    // Keyed objects (assets) stay on version 1: asset-storage-node hands their
    // keys to its readers by calling getEncryptionKeys itself, and that path
    // does not read the version.
    const keyVersion = this.encryptionSecret && key == null ? 2 : 1;

    const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(
      guild_id,
      channel_id,
      attachment_id,
      file_size,
      keyVersion,
    );

    const stream = await _downloadFile(
      url,
      encryptionKey,
      encryptionIv,
      this.downloadIp,
    );

    const { writeStream, promise } = this.uploadStream({
      Bucket: this.s3FileBucket,
      Key: fileName,
      Metadata: keyVersion === 2 ? { [KEY_VERSION_METADATA]: "2" } : undefined,
    });

    stream.pipe(writeStream);

    return promise;
  }

  async fetchFile(
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    file_size: number,
    quark_premium: boolean,
    key = null,
    extendedExpiration = false,
  ) {
    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key,
      extendedExpiration,
    );

    const raw = await this.fetchFileRaw(
      `${this.s3Url}${this.s3FileBucket}`,
      fileName,
    );

    if (!raw.Body) {
      throw new Error("File body is null");
    }

    // The object says which derivation it was written with, so files stored
    // before the secret was set stay readable until they expire.
    let encryptionKey: string;
    let encryptionIv: string;
    try {
      ({ key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(
        guild_id,
        channel_id,
        attachment_id,
        file_size,
        raw.Metadata?.[KEY_VERSION_METADATA] === "2" ? 2 : 1,
      ));
    } catch (error) {
      // The response body is already open. Left unread it would hold its
      // connection in the shared pool until the socket timed out.
      // @ts-ignore the Node body is a Readable
      raw.Body.destroy?.();
      throw error;
    }

    const stream = _fetchFile(
      // @ts-ignore this works
      raw.Body,
      encryptionKey,
      encryptionIv,
    );

    /**
     * Fail HERE, inside the caller's try/catch, rather than later.
     *
     * The decompressor only sees the first bytes when something starts
     * reading the stream — which in serverlog is the multipart body of the
     * webhook POST, long after `fetchFile` has returned. A stored object that
     * is not valid Brotli/zstd (`Unknown frame descriptor`, ~130/h on main)
     * therefore surfaced as an unhandled `error` event on a stream nobody was
     * listening to: an uncaught exception at process level and a failed send,
     * instead of a log sent without its attachment. Waiting for the first
     * readable chunk (or the error) before returning turns it back into an
     * ordinary rejection the existing `catch` around every call already
     * handles.
     */
    await primeStream(stream);

    return {
      stream,
      size: raw.ContentLength,
      name: fileName,
    };
  }

  async fetchFileRaw(bucket: string, key: string) {
    let raw;

    try {
      raw = await this.s3Files.send(
        new GetObjectCommand({
          Bucket: bucket,
          Key: key,
        }),
      );
    } catch (error: unknown) {
      // @ts-ignore this works
      if (error.statusCode == 404) {
        await sleep(10000);
        raw = await this.s3Files.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key: key,
          }),
        );
      } else throw error;
    }

    return raw;
  }

  deleteFile(name: string) {
    return this.s3Files.send(
      new DeleteObjectCommand({
        Bucket: `${this.s3Url}${this.s3FileBucket}`,
        Key: name,
      }),
    );
  }

  bulkDeleteFiles(files: string[]) {
    return this.s3Files.send(
      new DeleteObjectsCommand({
        Bucket: `${this.s3Url}${this.s3FileBucket}`,
        Delete: {
          Objects: files.map((file) => ({ Key: file })),
        },
      }),
    );
  }

  async checkFileExists(
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key = null,
    extendedExpiration = false,
  ) {
    const fileName = this.getFileName(
      attachment_id,
      channel_id,
      guild_id,
      quark_premium,
      key,
      extendedExpiration,
    );

    try {
      await this.s3Files.send(
        new HeadObjectCommand({
          Bucket: `${this.s3Url}${this.s3FileBucket}`,
          Key: fileName,
        }),
      );

      return true;
    } catch (error) {
      return false;
    }
  }
}
