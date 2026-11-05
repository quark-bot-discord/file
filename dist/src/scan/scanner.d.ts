import { Readable } from "stream";
import type { PdqFrames, PdqResult } from "./pdq.js";
import type { Quarantine, QuarantineSubject } from "../quarantine/index.js";
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
    /** Base64 PDQ hash of the first frame. */
    hash: string;
    /** Every frame's hash that was looked up, base64. */
    hashes?: string[];
    /** Frames in the file, and how many were hashed. */
    frames?: {
        total: number;
        checked: number;
    };
} | ({
    status: "match";
    /** Base64 PDQ hash of the frame that matched. */
    hash: string;
    provider: string;
    /** Which frame matched (0 for a still image). */
    frame?: number;
    hashes?: string[];
    frames?: {
        total: number;
        checked: number;
    };
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
    /** Where it was found: a logged attachment, an asset, a dashboard upload. */
    source?: "bot" | "assets" | "dashboard";
    provider: string;
    category: string;
    match_type: string | null;
    /** Base64 PDQ hash of the frame that matched. */
    pdq: string;
    /** Which frame of an animation matched. */
    frame?: number;
    /** Every frame hash that was looked up, base64. */
    hashes?: string[];
    /** Frames in the file, and how many were checked. */
    frames?: {
        total: number;
        checked: number;
    };
    /** The matcher's identifier for the database entry that matched. */
    reference?: string;
    guild_id: string;
    channel_id?: string;
    attachment_id?: string;
    /** The Discord account that posted or uploaded it, when known. */
    user_id?: string;
    /** Object name in the bucket (a marker at `store`, the file at `reupload`). */
    object?: string;
    /** The dashboard route an upload came to. */
    route?: string;
    /** Whatever the caller passed, e.g. message_id and user_id. */
    context?: Record<string, string>;
}
/**
 * What goes into quarantine with a detection, besides the detection itself.
 * None of it is ever sent in the alert.
 */
export interface DetectionEvidence {
    /** The file itself, exactly as it was received. */
    content?: Buffer;
    /** Its type, e.g. image/png. */
    contentType?: string;
    /** Its name, as the uploader gave it. */
    fileName?: string;
    /** Who sent it and from where, as far as the caller knows. */
    subject?: QuarantineSubject;
    /**
     * The relevant data about that person from the two weeks before, as the
     * caller holds it. Called only on a match. Errors are recorded, not thrown.
     */
    relevantData?: () => unknown | Promise<unknown>;
}
export declare class Scanner {
    matcher: Matcher;
    hasher: (image: Buffer) => Promise<PdqResult>;
    frameHasher: (image: Buffer, maxFrames: number) => Promise<PdqFrames>;
    maxFrames: number;
    quarantine?: Quarantine;
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
    constructor({ matcher, hasher, frameHasher, maxFrames, quarantine, maxBytes, concurrency, maxWaiting, maxWaitMs, readTimeoutMs, failClosed, onDetection, alertWebhook, }: {
        matcher: Matcher;
        /** Computes the hash of one frame. Only replaced in tests. */
        hasher?: (image: Buffer) => Promise<PdqResult>;
        /** Computes the hash of each frame. Only replaced in tests. */
        frameHasher?: (image: Buffer, maxFrames: number) => Promise<PdqFrames>;
        /**
         * Frames of an animated GIF or WebP that are checked. Past this many,
         * this many are checked, spread evenly from the first to the last.
         */
        maxFrames?: number;
        /** Where a matched file and its data are kept for a report. */
        quarantine?: Quarantine;
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
    /**
     * Check one whole file held in memory. Every frame of an animation is
     * checked, up to `maxFrames`. Never throws.
     */
    check(file: Buffer): Promise<Verdict>;
    /** One hash looked up, through the cache. Throws if the matcher fails. */
    private lookupOne;
    /**
     * Check a file that is still a stream. An image is read into memory, checked,
     * and handed back as a new stream over the same bytes. Anything that is not
     * read into memory is handed back as the same stream, unread.
     * Rejects only if the stream itself fails or stalls.
     */
    scanStream(source: NodeJS.ReadableStream, size: number, stage: ScanStage): Promise<{
        verdict: Verdict;
        stream: Readable;
        file?: Buffer;
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
     * Record a match: a log line, the quarantine, the caller's callback, and the
     * alert webhook. The alert carries identifiers and hashes only: never the
     * file, a link to it, or anything about the person beyond their id.
     *
     * Resolves with the quarantine id, or undefined when nothing was kept
     * (no quarantine configured, a repeat, or the write failed: each logged).
     * Never rejects.
     */
    report(detection: Detection, evidence?: DetectionEvidence): Promise<string | undefined>;
    private alert;
}
