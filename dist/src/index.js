import hashjs from "hash.js";
const { sha512 } = hashjs;
import { createHmac } from "crypto";
import { PassThrough } from "stream";
import { Upload } from "@aws-sdk/lib-storage";
import { PutBucketLifecycleConfigurationCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand, S3Client, NoSuchKey, DeleteObjectsCommand, PutObjectCommand, } from "@aws-sdk/client-s3";
import { downloadFile as _downloadFile } from "./core/downloadFile.js";
import { fetchFile as _fetchFile } from "./core/fetchFile.js";
import { checkMaxAttachmentSize } from "./util/checkMaxAttachmentSize.js";
import { sortFiles } from "./util/sortFiles.js";
import { FileWithheld, Scanner, scannerFromEnv } from "./scan/index.js";
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
function primeStream(stream) {
    return new Promise((resolve, reject) => {
        const done = (err) => {
            stream.removeListener("readable", onReadable);
            stream.removeListener("end", onEnd);
            stream.removeListener("error", onError);
            if (err)
                reject(err);
            else
                resolve();
        };
        const onReadable = () => done();
        const onEnd = () => done();
        const onError = (err) => done(err);
        stream.once("readable", onReadable);
        stream.once("end", onEnd);
        stream.once("error", onError);
    });
}
const sleep = (period) => new Promise((resolve, reject) => setTimeout(resolve, period));
export { checkMaxAttachmentSize, sortFiles, NoSuchKey, _fetchFile, _downloadFile, FileWithheld, Scanner, };
export { ArachnidShieldMatcher, scannerFromEnv } from "./scan/index.js";
/**
 * S3 user-metadata key recording which key derivation an object was written
 * with. Absent means 1.
 */
const KEY_VERSION_METADATA = "kv";
/**
 * S3 user-metadata key on a marker object: an empty object stored in place of
 * a file that matched at download, holding the reason, so the log written when
 * the message is deleted can say why there is no file.
 */
const WITHHELD_METADATA = "withheld";
/** S3 user-metadata key set to "clear" on a file that passed the check when stored. */
const SCAN_METADATA = "scan";
export default class FileStorage {
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey, s3Region, fileExpirationDaysStandard, fileExpirationDaysExtended, fileExpirationDaysUltraExtended, downloadIp, encryptionSecret, scanner, }) {
        this.downloadIp = downloadIp;
        this.scanner = scanner === null ? undefined : (scanner ?? scannerFromEnv());
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
        this.s3Files.send(new PutBucketLifecycleConfigurationCommand({
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
        }));
    }
    uploadStream({ Bucket, Key, Metadata, }) {
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
    checkMaxAttachmentSize(premium_tier) {
        return checkMaxAttachmentSize(premium_tier);
    }
    sortFiles(files, maxSize) {
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
    getEncryptionKeys(guild_id, channel_id, attachment_id, file_size, version = 1) {
        if (version === 2) {
            if (!this.encryptionSecret) {
                throw new Error("File was encrypted with a secret this process does not have (FILE_ENCRYPTION_SECRET)");
            }
            const ids = `${String(guild_id)}:${String(channel_id)}:${String(attachment_id)}:${String(file_size)}`;
            const derive = (label) => createHmac("sha512", this.encryptionSecret)
                .update(`${label}:${ids}`)
                .digest("hex");
            return {
                key: derive("key").slice(0, 32),
                iv: derive("iv").slice(0, 16),
            };
        }
        return {
            key: sha512()
                .update(`${sha512()
                .update(`${String(guild_id)}${String(channel_id)}${String(attachment_id)}${String(file_size)}`)
                .digest("hex")}satoshiNakamoto`)
                .digest("hex")
                .slice(0, 32),
            iv: sha512()
                .update(`${sha512()
                .update(`${String(guild_id)}${String(channel_id)}${String(attachment_id)}`)
                .digest("hex")}${String(file_size)}`)
                .digest("hex")
                .slice(0, 16),
        };
    }
    getFileName(attachment_id, channel_id, guild_id, quark_premium, key = null, extendedExpiration = false) {
        const stringToHash = `${attachment_id}/${channel_id}/${guild_id}`;
        return `${extendedExpiration ? "2_" : ""}${key != null ? `${key}_` : ""}${quark_premium == true ? "1" : "0"}_${sha512().update(stringToHash).digest("hex")}.enc`;
    }
    async downloadFile(url, guild_id, channel_id, attachment_id, premium_tier, file_size, quark_premium, key = null, extendedExpiration = false, 
    /** Identifiers to include if the file is reported, e.g. message_id. */
    context) {
        const maxFileSize = this.checkMaxAttachmentSize(premium_tier);
        if (maxFileSize < file_size)
            throw new Error("File too big");
        const fileName = this.getFileName(attachment_id, channel_id, guild_id, quark_premium, key, extendedExpiration);
        // Keyed objects (assets) stay on version 1: asset-storage-node hands their
        // keys to its readers by calling getEncryptionKeys itself, and that path
        // does not read the version.
        const keyVersion = this.encryptionSecret && key == null ? 2 : 1;
        const { key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(guild_id, channel_id, attachment_id, file_size, keyVersion);
        const scanner = this.scanner;
        // Set by the callback below; a property so the compiler does not assume
        // it is still undefined afterwards.
        const scan = {};
        let stream;
        try {
            stream = await _downloadFile(url, encryptionKey, encryptionIv, this.downloadIp, scanner &&
                (async (body) => {
                    const scanned = await scanner.scanStream(body, file_size, "store");
                    scan.verdict = scanned.verdict;
                    if (scanned.verdict.status === "match") {
                        scanned.stream.destroy();
                        throw new FileWithheld(scanned.verdict.category, "store");
                    }
                    // An image that could not be checked this time must not replace
                    // the marker left when an earlier download of it matched (a
                    // message edit downloads every attachment again).
                    if (scanned.verdict.status === "error" && key == null) {
                        let marked;
                        try {
                            marked = await this.withheldMarker(fileName);
                        }
                        catch (error) {
                            scanned.stream.destroy();
                            throw error;
                        }
                        if (marked) {
                            scanned.stream.destroy();
                            throw new FileWithheld(marked, "store");
                        }
                    }
                    return scanned.stream;
                }));
        }
        catch (error) {
            const verdict = scan.verdict;
            if (scanner &&
                error instanceof FileWithheld &&
                verdict?.status === "match") {
                // Nothing is stored. For a message attachment, leave a marker so the
                // delete log can say why. Assets are read by other code that does not
                // know about markers, so they simply stay absent.
                if (key == null) {
                    await this.s3Files
                        .send(new PutObjectCommand({
                        Bucket: `${this.s3Url}${this.s3FileBucket}`,
                        Key: fileName,
                        Body: "",
                        Metadata: { [WITHHELD_METADATA]: verdict.category },
                    }))
                        .catch((markerError) => console.error(`[FILE SCAN] could not write marker ${fileName}: ${markerError.message}`));
                }
                scanner.report({
                    time: new Date().toISOString(),
                    stage: "store",
                    provider: verdict.provider,
                    category: verdict.category,
                    match_type: verdict.matchType,
                    pdq: verdict.hash,
                    reference: verdict.reference,
                    guild_id: String(guild_id),
                    channel_id: String(channel_id),
                    attachment_id: String(attachment_id),
                    object: fileName,
                    context,
                });
            }
            throw error;
        }
        const metadata = {};
        if (keyVersion === 2)
            metadata[KEY_VERSION_METADATA] = "2";
        if (scan.verdict?.status === "clear")
            metadata[SCAN_METADATA] = "clear";
        const { writeStream, promise } = this.uploadStream({
            Bucket: this.s3FileBucket,
            Key: fileName,
            Metadata: Object.keys(metadata).length !== 0 ? metadata : undefined,
        });
        stream.pipe(writeStream);
        return promise;
    }
    async fetchFile(guild_id, channel_id, attachment_id, file_size, quark_premium, key = null, extendedExpiration = false, 
    /** Identifiers to include if the file is reported, e.g. message_id. */
    context) {
        const fileName = this.getFileName(attachment_id, channel_id, guild_id, quark_premium, key, extendedExpiration);
        const raw = await this.fetchFileRaw(`${this.s3Url}${this.s3FileBucket}`, fileName);
        // A marker, not a file: it matched when it was downloaded and was never
        // stored. Honoured even with no scanner configured.
        const withheld = raw.Metadata?.[WITHHELD_METADATA];
        if (withheld) {
            // @ts-ignore the Node body is a Readable
            raw.Body?.destroy?.();
            throw new FileWithheld(withheld, "store");
        }
        if (!raw.Body) {
            throw new Error("File body is null");
        }
        // The object says which derivation it was written with, so files stored
        // before the secret was set stay readable until they expire.
        let encryptionKey;
        let encryptionIv;
        try {
            ({ key: encryptionKey, iv: encryptionIv } = this.getEncryptionKeys(guild_id, channel_id, attachment_id, file_size, raw.Metadata?.[KEY_VERSION_METADATA] === "2" ? 2 : 1));
        }
        catch (error) {
            // The response body is already open. Left unread it would hold its
            // connection in the shared pool until the socket timed out.
            // @ts-ignore the Node body is a Readable
            raw.Body.destroy?.();
            throw error;
        }
        const stream = _fetchFile(
        // @ts-ignore this works
        raw.Body, encryptionKey, encryptionIv);
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
        if (!this.scanner) {
            await primeStream(stream);
            return {
                stream,
                size: raw.ContentLength,
                name: fileName,
            };
        }
        // Checked again here because the database of known material grows: a
        // file that was clear when stored may match by the time it is re-uploaded.
        // Reading the first bytes also does what primeStream does above.
        const scanned = await this.scanner.scanStream(stream, file_size, "reupload");
        const verdict = scanned.verdict;
        if (verdict.status === "match") {
            scanned.stream.destroy();
            // @ts-ignore the Node body is a Readable
            raw.Body.destroy?.();
            this.scanner.report({
                time: new Date().toISOString(),
                stage: "reupload",
                provider: verdict.provider,
                category: verdict.category,
                match_type: verdict.matchType,
                pdq: verdict.hash,
                reference: verdict.reference,
                guild_id: String(guild_id),
                channel_id: String(channel_id),
                attachment_id: String(attachment_id),
                object: fileName,
                context,
            });
            throw new FileWithheld(verdict.category, "reupload");
        }
        if (verdict.status === "error" &&
            this.scanner.failClosed &&
            raw.Metadata?.[SCAN_METADATA] !== "clear") {
            scanned.stream.destroy();
            // @ts-ignore the Node body is a Readable
            raw.Body.destroy?.();
            throw new FileWithheld("unchecked", "reupload");
        }
        return {
            stream: scanned.stream,
            size: raw.ContentLength,
            name: fileName,
        };
    }
    /** The reason on a marker object, or undefined if there is no marker. */
    async withheldMarker(fileName) {
        try {
            const head = await this.s3Files.send(new HeadObjectCommand({
                Bucket: `${this.s3Url}${this.s3FileBucket}`,
                Key: fileName,
            }));
            return head.Metadata?.[WITHHELD_METADATA];
        }
        catch (error) {
            if (error?.name === "NotFound" ||
                error?.$metadata?.httpStatusCode === 404)
                return undefined;
            throw error;
        }
    }
    async fetchFileRaw(bucket, key) {
        let raw;
        try {
            raw = await this.s3Files.send(new GetObjectCommand({
                Bucket: bucket,
                Key: key,
            }));
        }
        catch (error) {
            // @ts-ignore this works
            if (error.statusCode == 404) {
                await sleep(10000);
                raw = await this.s3Files.send(new GetObjectCommand({
                    Bucket: bucket,
                    Key: key,
                }));
            }
            else
                throw error;
        }
        return raw;
    }
    deleteFile(name) {
        return this.s3Files.send(new DeleteObjectCommand({
            Bucket: `${this.s3Url}${this.s3FileBucket}`,
            Key: name,
        }));
    }
    bulkDeleteFiles(files) {
        return this.s3Files.send(new DeleteObjectsCommand({
            Bucket: `${this.s3Url}${this.s3FileBucket}`,
            Delete: {
                Objects: files.map((file) => ({ Key: file })),
            },
        }));
    }
    async checkFileExists(attachment_id, channel_id, guild_id, quark_premium, key = null, extendedExpiration = false) {
        const fileName = this.getFileName(attachment_id, channel_id, guild_id, quark_premium, key, extendedExpiration);
        try {
            await this.s3Files.send(new HeadObjectCommand({
                Bucket: `${this.s3Url}${this.s3FileBucket}`,
                Key: fileName,
            }));
            return true;
        }
        catch (error) {
            return false;
        }
    }
}
//# sourceMappingURL=index.js.map