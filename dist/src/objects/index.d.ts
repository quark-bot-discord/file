import type { ObjectClient } from "../quarantine/index.js";
export declare class ObjectStore {
    private client;
    private bucket;
    constructor(client: ObjectClient, bucket: string);
    put(key: string, body: Buffer, contentType: string): Promise<void>;
    /** The bytes, or null when there is no such object. */
    get(key: string): Promise<Buffer | null>;
}
export declare function objectStoreFromEnv(prefix: string, env?: NodeJS.ProcessEnv): ObjectStore | undefined;
