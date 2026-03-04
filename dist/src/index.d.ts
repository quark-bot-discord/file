import { PassThrough } from "stream";
import { S3Client, NoSuchKey } from "@aws-sdk/client-s3";
import { downloadFile as _downloadFile } from "./core/downloadFile.js";
import { fetchFile as _fetchFile } from "./core/fetchFile.js";
import { checkMaxAttachmentSize } from "./util/checkMaxAttachmentSize.js";
import { sortFiles } from "./util/sortFiles.js";
export { checkMaxAttachmentSize, sortFiles, NoSuchKey, _fetchFile, _downloadFile, };
export default class FileStorage {
    downloadIp?: string;
    s3Url: string;
    s3Region: string;
    s3FileBucket: string;
    s3Files: S3Client;
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey, s3Region, fileExpirationDaysStandard, fileExpirationDaysExtended, fileExpirationDaysUltraExtended, downloadIp, }: {
        s3Url: string;
        s3FileBucket: string;
        s3AccessKeyId: string;
        s3SecretAccessKey: string;
        s3Region: string;
        fileExpirationDaysStandard?: number;
        fileExpirationDaysExtended?: number;
        fileExpirationDaysUltraExtended?: number;
        downloadIp?: string;
    });
    uploadStream({ Bucket, Key }: {
        Bucket: string;
        Key: string;
    }): {
        writeStream: PassThrough;
        promise: Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    };
    checkMaxAttachmentSize(premium_tier: number): number;
    sortFiles(files: any[], maxSize: number): any[][];
    getEncryptionKeys(guild_id: string, channel_id: string, attachment_id: string, file_size: number): {
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
