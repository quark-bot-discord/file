export default class FileStorage {
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey, s3Region, fileExpirationDaysStandard, fileExpirationDaysExtended, fileExpirationDaysUltraExtended, downloadIp, }: {
        s3Url: any;
        s3FileBucket: any;
        s3AccessKeyId: any;
        s3SecretAccessKey: any;
        s3Region: any;
        fileExpirationDaysStandard: any;
        fileExpirationDaysExtended: any;
        fileExpirationDaysUltraExtended: any;
        downloadIp: any;
    });
    downloadIp: any;
    s3Url: any;
    s3Region: any;
    s3FileBucket: any;
    s3Files: S3Client;
    uploadStream({ Bucket, Key }: {
        Bucket: any;
        Key: any;
    }): {
        writeStream: any;
        promise: Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    };
    checkMaxAttachmentSize(premium_tier: any): 52420000 | 104840000 | 26110000;
    sortFiles(files: any, maxSize: any): Attachment[][];
    getEncryptionKeys(guild_id: any, channel_id: any, attachment_id: any, file_size: any): {
        key: any;
        iv: any;
    };
    getFileName(attachment_id: any, channel_id: any, guild_id: any, quark_premium: any, key?: any, extendedExpiration?: boolean): string;
    downloadFile(url: any, guild_id: any, channel_id: any, attachment_id: any, premium_tier: any, file_size: any, quark_premium: any, key?: any, extendedExpiration?: boolean): Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    fetchFile(guild_id: any, channel_id: any, attachment_id: any, file_size: any, quark_premium: any, key?: any, extendedExpiration?: boolean): Promise<{
        stream: Stream;
        size: number;
        name: string;
    }>;
    fetchFileRaw(bucket: any, key: any): Promise<import("@aws-sdk/client-s3").GetObjectCommandOutput>;
    deleteFile(name: any): Promise<import("@aws-sdk/client-s3").DeleteObjectCommandOutput>;
    bulkDeleteFiles(files: any): Promise<import("@aws-sdk/client-s3").DeleteObjectsCommandOutput>;
    checkFileExists(attachment_id: any, channel_id: any, guild_id: any, quark_premium: any, key?: any, extendedExpiration?: boolean): Promise<boolean>;
}
import checkMaxAttachmentSize from "./src/checkMaxAttachmentSize.js";
import sortFiles from "./src/sortFiles.js";
import { NoSuchKey } from "@aws-sdk/client-s3";
import _fetchFile from "./src/fetchFile.js";
import _downloadFile from "./src/downloadFile.js";
import { S3Client } from "@aws-sdk/client-s3";
export { checkMaxAttachmentSize, sortFiles, NoSuchKey, _fetchFile, _downloadFile };
