export default class FileStorage {
  constructor({
    s3Url,
    s3FileBucket,
    s3AccessKeyId,
    s3SecretAccessKey,
    s3Region,
    fileExpirationDaysStandard,
    fileExpirationDaysExtended,
  }: {
    s3Url: string;
    s3FileBucket: string;
    s3AccessKeyId: string;
    s3SecretAccessKey: string;
    s3Region: string;
    fileExpirationDaysStandard: number;
    fileExpirationDaysExtended: number;
  });
  s3Url: string;
  s3Region: string;
  s3FileBucket: string;
  s3Files: S3Client;
  uploadStream({ Bucket, Key }: { Bucket: string; Key: string }): {
    writeStream: any;
    promise: Promise<
      import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput
    >;
  };
  checkMaxAttachmentSize(premium_tier: number): 52420000 | 104840000 | 26110000;
  sortFiles(files: Attachment[], maxSize: number): Attachment[][];
  getEncryptionKeys(
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    file_size: number
  ): {
    key: any;
    iv: any;
  };
  getFileName(
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key?: string
  ): string;
  downloadFile(
    url: string,
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    premium_tier: number,
    file_size: number,
    quark_premium: boolean,
    key?: string
  ): Promise<import("@aws-sdk/client-s3").CompleteMultipartUploadCommandOutput>;
  fetchFile(
    guild_id: string,
    channel_id: string,
    attachment_id: string,
    file_size: number,
    quark_premium: boolean,
    key?: string
  ): Promise<{
    stream: Stream;
    size: number;
    name: string;
  }>;
  deleteFile(
    name: any
  ): Promise<import("@aws-sdk/client-s3").DeleteObjectCommandOutput>;
  checkFileExists(
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key?: string
  ): Promise<boolean>;
}
import checkMaxAttachmentSize from "./src/checkMaxAttachmentSize.js";
import sortFiles from "./src/sortFiles.js";
import { S3Client } from "@aws-sdk/client-s3";
export { checkMaxAttachmentSize, sortFiles };
