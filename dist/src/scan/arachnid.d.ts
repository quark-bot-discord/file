import type { Match, Matcher } from "./scanner.js";
/**
 * Looks PDQ hashes up in Project Arachnid Shield (Canadian Centre for Child
 * Protection). Only the hash is sent: `POST /v1/pdq` with
 * `{ "hashes": [<base64>, ...] }`. The file never leaves this process.
 *
 * Lookups made within `batchWindowMs` of each other share one request.
 */
export declare class ArachnidShieldMatcher implements Matcher {
    name: string;
    private url;
    private authorization;
    private timeoutMs;
    private batchWindowMs;
    private batchSize;
    private queue;
    private timer?;
    constructor({ username, password, baseUrl, timeoutMs, batchWindowMs, batchSize, }: {
        username: string;
        password: string;
        baseUrl?: string;
        timeoutMs?: number;
        batchWindowMs?: number;
        batchSize?: number;
    });
    lookup(hash: Buffer): Promise<Match | null>;
    private flush;
    private send;
}
