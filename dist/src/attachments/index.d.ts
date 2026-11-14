import type { ObjectClient } from "../quarantine/index.js";
export interface AttachmentRef {
    guildId: string;
    channelId: string;
    attachmentId: string;
}
export interface FoundCopy {
    name: string;
    /** The original size, when the copy recorded it. */
    size: number | null;
    keyVersion: 1 | 2;
    /** A marker left when the image check matched at download: no file. */
    withheld: string | null;
}
/** `.../attachments/<channel_id>/<attachment_id>/<filename>` */
export declare function attachmentFromUrl(url: string): {
    channelId: string;
    attachmentId: string;
} | null;
/** Every name one stored copy can have. */
export declare function storedNames(ref: AttachmentRef, keys?: string[]): string[];
export declare class AttachmentStore {
    private client;
    private bucket;
    private encryptionSecret;
    constructor(client: ObjectClient, bucket: string, encryptionSecret?: string | undefined);
    get bucketName(): string;
    find(ref: AttachmentRef, keys?: string[]): Promise<FoundCopy[]>;
    /**
     * The original bytes of the first copy that can be decrypted, trying the
     * recorded size and then each of `sizes`. Null when there is no copy, or
     * none of the sizes opens it (`tried` says which were tried).
     */
    read(ref: AttachmentRef, sizes?: number[]): Promise<{
        bytes: Buffer;
        size: number;
        name: string;
    } | {
        bytes: null;
        tried: number[];
        copies: number;
    }>;
    /** Deletes every stored name of the copy; the names that were there. */
    delete(ref: AttachmentRef, keys?: string[]): Promise<string[]>;
}
/**
 * One store per bucket, from the environment:
 *
 *   FILES_S3_URL, FILES_S3_REGION, FILES_S3_ACCESS_KEY_ID,
 *   FILES_S3_SECRET_ACCESS_KEY, and the buckets as FILES_BUCKETS, a comma
 *   list of `variant:bucket` (e.g. `main:files,pro:files-pro`).
 *
 * Empty when any is missing.
 */
export declare function attachmentStoresFromEnv(env?: NodeJS.ProcessEnv): {
    variant: string;
    store: AttachmentStore;
}[];
