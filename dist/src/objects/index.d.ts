import type { ObjectClient } from "../quarantine/index.js";
export declare class ObjectStore {
    private client;
    private bucket;
    constructor(client: ObjectClient, bucket: string);
    put(key: string, body: Buffer, contentType: string): Promise<void>;
    /** The bytes, or null when there is no such object. */
    get(key: string): Promise<Buffer | null>;
    /**
     * Deletes the object. True when it was there, false when it was already
     * gone; an S3 delete of a missing key succeeds, so it is looked for first.
     */
    delete(key: string): Promise<boolean>;
}
export declare function objectStoreFromEnv(prefix: string, env?: NodeJS.ProcessEnv): ObjectStore | undefined;
