/**
 * A plain S3 bucket for an app's own small files, configured from the
 * environment under a prefix. The website keeps log avatars uploaded on the
 * dashboard here (`LOG_AVATAR_*`), after the image check.
 *
 *   <PREFIX>_BUCKET, <PREFIX>_S3_URL, <PREFIX>_S3_REGION,
 *   <PREFIX>_S3_ACCESS_KEY_ID, <PREFIX>_S3_SECRET_ACCESS_KEY
 */
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
export class ObjectStore {
    constructor(client, bucket) {
        this.client = client;
        this.bucket = bucket;
    }
    async put(key, body, contentType) {
        await this.client.send(new PutObjectCommand({
            Bucket: this.bucket,
            Key: key,
            Body: body,
            ContentType: contentType,
        }));
    }
    /** The bytes, or null when there is no such object. */
    async get(key) {
        try {
            const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
            return Buffer.from(await res.Body.transformToByteArray());
        }
        catch (error) {
            if (error?.name === "NoSuchKey" || error?.$metadata?.httpStatusCode === 404)
                return null;
            throw error;
        }
    }
}
export function objectStoreFromEnv(prefix, env = process.env) {
    const bucket = env[`${prefix}_BUCKET`];
    const endpoint = env[`${prefix}_S3_URL`];
    const accessKeyId = env[`${prefix}_S3_ACCESS_KEY_ID`];
    const secretAccessKey = env[`${prefix}_S3_SECRET_ACCESS_KEY`];
    if (!bucket || !endpoint || !accessKeyId || !secretAccessKey)
        return undefined;
    return new ObjectStore(new S3Client({
        endpoint,
        region: env[`${prefix}_S3_REGION`] || "garage",
        forcePathStyle: true,
        credentials: { accessKeyId, secretAccessKey },
    }), bucket);
}
//# sourceMappingURL=index.js.map