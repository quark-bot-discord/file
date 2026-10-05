import { Readable } from "stream";
import type { PdqResult } from "./pdq.js";
import type { ScanStage } from "./withheld.js";
export interface Match {
    /** The matcher's classification, e.g. `csam`. */
    category: string;
    /** `exact`, `near`, or null if the matcher does not say. */
    matchType: string | null;
    /** The matcher's identifier for the database entry that matched, if any. */
    reference?: string;
}
/** A service that answers "is this hash known?". It is only ever given a hash. */
export interface Matcher {
    name: string;
    lookup(hash: Buffer): Promise<Match | null>;
}
export type Verdict = {
    status: "clear";
    hash: string;
} | ({
    status: "match";
    hash: string;
    provider: string;
} & Match)
/** Nothing to check: not an image, or an image with no features to hash. */
 | {
    status: "skipped";
    reason: string;
}
/**
 * An image that should have been checked and was not: the matcher or the
 * hasher is unavailable, the scanner is busy, or the image is too large or
 * cannot be decoded.
 */
 | {
    status: "error";
    reason: string;
};
export interface Detection {
    time: string;
    stage: ScanStage;
    provider: string;
    category: string;
    match_type: string | null;
    /** Base64 PDQ hash of the file. */
    pdq: string;
    /** The matcher's identifier for the database entry that matched. */
    reference?: string;
    guild_id: string;
    channel_id: string;
    attachment_id: string;
    /** Object name in the bucket (a marker at `store`, the file at `reupload`). */
    object: string;
    /** Whatever the caller passed, e.g. message_id and user_id. */
    context?: Record<string, string>;
}
export declare class Scanner {
    matcher: Matcher;
    hasher: (image: Buffer) => Promise<PdqResult>;
    maxBytes: number;
    failClosed: boolean;
    onDetection?: (detection: Detection) => void;
    alertWebhook?: string;
    concurrency: number;
    private maxWaiting;
    private maxWaitMs;
    private readTimeoutMs;
    private active;
    private waiting;
    private cache;
    private reported;
    private lastComplaint;
    constructor({ matcher, hasher, maxBytes, concurrency, maxWaiting, maxWaitMs, readTimeoutMs, failClosed, onDetection, alertWebhook, }: {
        matcher: Matcher;
        /** Computes the hash. Only replaced in tests. */
        hasher?: (image: Buffer) => Promise<PdqResult>;
        /** Images larger than this are not read into memory and so not checked. */
        maxBytes?: number;
        /**
         * Images held in memory and hashed at once. One decode is allowed up to
         * about 150 MB, so this bounds what a burst of hostile images can take.
         */
        concurrency?: number;
        /** At `store`, give up rather than queue behind more than this many. */
        maxWaiting?: number;
        /** Give up waiting for a turn after this long. */
        maxWaitMs?: number;
        /** Give up reading one image into memory after this long. */
        readTimeoutMs?: number;
        /**
         * What happens before a re-upload to an image that could not be checked:
         * true withholds it unless it passed the check when it was stored; false
         * lets it through.
         */
        failClosed?: boolean;
        onDetection?: (detection: Detection) => void;
        /** Discord webhook URL that receives one message per detection. */
        alertWebhook?: string;
    });
    /** Check one whole file held in memory. Never throws. */
    check(file: Buffer): Promise<Verdict>;
    /**
     * Check a file that is still a stream. An image is read into memory, checked,
     * and handed back as a new stream over the same bytes. Anything that is not
     * read into memory is handed back as the same stream, unread.
     * Rejects only if the stream itself fails or stalls.
     */
    scanStream(source: NodeJS.ReadableStream, size: number, stage: ScanStage): Promise<{
        verdict: Verdict;
        stream: Readable;
    }>;
    private acquire;
    private release;
    /** A loud log line, at most once a minute. */
    private complain;
    /**
     * Hash a built-in image and make one lookup, and log whether each worked,
     * so a missing native module or wrong credentials show up at start-up
     * rather than as files silently going unchecked.
     */
    selfTest(): Promise<boolean>;
    /**
     * Record a match: a log line, the caller's callback, and the alert webhook.
     * Identifiers and hashes only. Never the file, never a link to it.
     */
    report(detection: Detection): void;
    private alert;
}
