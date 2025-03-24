export default class FileStorage {
    constructor({ s3Url, s3FileBucket, s3AccessKeyId, s3SecretAccessKey, s3Region, fileExpirationDaysStandard, fileExpirationDaysExtended, downloadIp }: {
        s3Url: any;
        s3FileBucket: any;
        s3AccessKeyId: any;
        s3SecretAccessKey: any;
        s3Region: any;
        fileExpirationDaysStandard: any;
        fileExpirationDaysExtended: any;
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
    getFileName(attachment_id: any, channel_id: any, guild_id: any, quark_premium: any, key?: any): string;
    downloadFile(url: any, guild_id: any, channel_id: any, attachment_id: any, premium_tier: any, file_size: any, quark_premium: any, key?: any): Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
    fetchFile(guild_id: any, channel_id: any, attachment_id: any, file_size: any, quark_premium: any, key?: any): Promise<{
        stream: Stream;
        size: number;
        name: string;
    }>;
    deleteFile(name: any): Promise<import("@aws-sdk/client-s3").DeleteObjectCommandOutput>;
    checkFileExists(attachment_id: any, channel_id: any, guild_id: any, quark_premium: any, key?: any): Promise<boolean>;
}
import checkMaxAttachmentSize from "./src/checkMaxAttachmentSize.js";
import sortFiles from "./src/sortFiles.js";
import { S3Client } from "@aws-sdk/client-s3";
export { checkMaxAttachmentSize, sortFiles };
