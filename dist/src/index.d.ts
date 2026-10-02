import { PassThrough } from "stream";
import { S3Client, NoSuchKey } from "@aws-sdk/client-s3";
import { downloadFile as _downloadFile } from "./core/downloadFile.js";
import { fetchFile as _fetchFile } from "./core/fetchFile.js";
import { checkMaxAttachmentSize } from "./util/checkMaxAttachmentSize.js";
import { sortFiles } from "./util/sortFiles.js";
export { checkMaxAttachmentSize, sortFiles, NoSuchKey, _fetchFile, _downloadFile, };
export default class FileStorage {
    downloadIp?: string;
    encryptionSecret?: string;
    s3Url: string;
    s3Region: string;
    s3FileBucket: string;
    s3Files: S3Client;
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey, s3Region, fileExpirationDaysStandard, fileExpirationDaysExtended, fileExpirationDaysUltraExtended, downloadIp, encryptionSecret, }: {
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
    });
    uploadStream({ Bucket, Key, Metadata, }: {
        Bucket: string;
        Key: string;
        Metadata?: Record<string, string>;
    }): {
        writeStream: PassThrough;
        promise: Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    };
    checkMaxAttachmentSize(premium_tier: number): number;
    sortFiles(files: any[], maxSize: number): any[][];
    /**
     * Version 1 derives the key from the ids, the size and a constant, all of
     * which are known to anyone who could see the message, so it only protects
     * against someone who has the stored objects and nothing else.
     *
     * Version 2 keys the derivation with `encryptionSecret`: the stored objects
     * are unreadable without a secret that never sits in the bucket.
     */
    getEncryptionKeys(guild_id: string, channel_id: string, attachment_id: string, file_size: number, version?: 1 | 2): {
        key: string;
        iv: string;
    };
    getFileName(attachment_id: string, channel_id: string, guild_id: string, quark_premium: boolean, key?: null, extendedExpiration?: boolean): string;
    downloadFile(url: string, guild_id: string, channel_id: string, attachment_id: string, premium_tier: number, file_size: number, quark_premium: boolean, key?: null, extendedExpiration?: boolean): Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    fetchFile(guild_id: string, channel_id: string, attachment_id: string, file_size: number, quark_premium: boolean, key?: null, extendedExpiration?: boolean): Promise<{
        stream: NodeJS.ReadableStream;
        size: number | undefined;
        name: string;
    }>;
    fetchFileRaw(bucket: string, key: string): Promise<import("@aws-sdk/client-s3").GetObjectCommandOutput>;
    deleteFile(name: string): Promise<import("@aws-sdk/client-s3").DeleteObjectCommandOutput>;
    bulkDeleteFiles(files: string[]): Promise<import("@aws-sdk/client-s3").DeleteObjectsCommandOutput>;
    checkFileExists(attachment_id: string, channel_id: string, guild_id: string, quark_premium: boolean, key?: null, extendedExpiration?: boolean): Promise<boolean>;
}
