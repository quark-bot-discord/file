/**
 * A plain S3 bucket for an app's own small files, configured from the
 * environment under a prefix. The website keeps log avatars uploaded on the
 * dashboard here (`LOG_AVATAR_*`), after the image check, and an admin
 * takedown deletes them again (`delete`).
 *
 *   <PREFIX>_BUCKET, <PREFIX>_S3_URL, <PREFIX>_S3_REGION,
 *   <PREFIX>_S3_ACCESS_KEY_ID, <PREFIX>_S3_SECRET_ACCESS_KEY
 */
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import type { ObjectClient } from "../quarantine/index.js";

export class ObjectStore {
  constructor(
    private client: ObjectClient,
    private bucket: string,
  ) {}

  async put(key: string, body: Buffer, contentType: string) {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
      }),
    );
  }

  /** The bytes, or null when there is no such object. */
  async get(key: string): Promise<Buffer | null> {
    try {
      const res = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return Buffer.from(await res.Body.transformToByteArray());
    } catch (error: any) {
      if (error?.name === "NoSuchKey" || error?.$metadata?.httpStatusCode === 404)
        return null;
      throw error;
    }
  }

  /**
   * Deletes the object. True when it was there, false when it was already
   * gone; an S3 delete of a missing key succeeds, so it is looked for first.
   */
  async delete(key: string): Promise<boolean> {
    const there = (await this.get(key)) !== null;
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    return there;
  }
}

export function objectStoreFromEnv(
  prefix: string,
  env: NodeJS.ProcessEnv = process.env,
): ObjectStore | undefined {
  const bucket = env[`${prefix}_BUCKET`];
  const endpoint = env[`${prefix}_S3_URL`];
  const accessKeyId = env[`${prefix}_S3_ACCESS_KEY_ID`];
  const secretAccessKey = env[`${prefix}_S3_SECRET_ACCESS_KEY`];
  if (!bucket || !endpoint || !accessKeyId || !secretAccessKey) return undefined;
  return new ObjectStore(
    new S3Client({
      endpoint,
      region: env[`${prefix}_S3_REGION`] || "garage",
      forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey },
    }),
    bucket,
  );
}
