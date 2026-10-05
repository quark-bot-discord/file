import { Readable } from "stream";
import { HasherUnavailable, pdqHash, TooManyPixels } from "./pdq.js";
import { isHashableImage, SNIFF_BYTES } from "./sniff.js";
/** A 1x1 PNG. */
const SELF_TEST_IMAGE = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "base64");
const CACHE_ENTRIES = 20000;
const CACHE_MS = 10 * 60 * 1000;
/** Meta's guidance: a PDQ hash with quality under 50 says nothing useful. */
const MIN_QUALITY = 50;
/**
 * The first `bytes` of a stream, put back afterwards so the stream can still
 * be read from the start. `ended` means the whole stream was shorter than
 * that and has been used up.
 */
function peek(stream, bytes) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let length = 0;
        const cleanup = () => {
            stream.removeListener("readable", onReadable);
            stream.removeListener("end", onEnd);
            stream.removeListener("error", onError);
        };
        const onReadable = () => {
            let chunk;
            while (length < bytes && (chunk = stream.read())) {
                chunks.push(chunk);
                length += chunk.length;
            }
            if (length >= bytes) {
                cleanup();
                const head = Buffer.concat(chunks);
                stream.unshift(head);
                resolve({ head, ended: false });
            }
        };
        const onEnd = () => {
            cleanup();
            resolve({ head: Buffer.concat(chunks), ended: true });
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        stream.on("readable", onReadable);
        stream.once("end", onEnd);
        stream.once("error", onError);
    });
}
/** The whole stream in memory. Gives up past `limit` bytes or `timeoutMs`. */
function readAll(stream, limit, timeoutMs) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let length = 0;
        const cleanup = () => {
            clearTimeout(timer);
            stream.removeListener("data", onData);
            stream.removeListener("end", onEnd);
            stream.removeListener("error", onError);
        };
        const abandon = (error) => {
            cleanup();
            // Swallow whatever the stream emits while it is torn down.
            stream.on("error", () => { });
            stream.destroy();
            reject(error);
        };
        const onData = (chunk) => {
            chunks.push(chunk);
            length += chunk.length;
            if (length > limit)
                abandon(new Error("File is larger than declared"));
        };
        const onEnd = () => {
            cleanup();
            resolve(Buffer.concat(chunks));
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        const timer = setTimeout(() => abandon(new Error("Timed out reading the file to check it")), timeoutMs);
        stream.on("data", onData);
        stream.once("end", onEnd);
        stream.once("error", onError);
    });
}
export class Scanner {
    constructor({ matcher, hasher = pdqHash, maxBytes = 32 * 1024 * 1024, concurrency = 2, maxWaiting = 200, maxWaitMs = 20000, readTimeoutMs = 30000, failClosed = true, onDetection, alertWebhook, }) {
        this.active = 0;
        this.waiting = [];
        this.cache = new Map();
        this.reported = new Set();
        this.lastComplaint = 0;
        this.matcher = matcher;
        this.hasher = hasher;
        this.maxBytes = maxBytes;
        this.concurrency = concurrency;
        this.maxWaiting = maxWaiting;
        this.maxWaitMs = maxWaitMs;
        this.readTimeoutMs = readTimeoutMs;
        this.failClosed = failClosed;
        this.onDetection = onDetection;
        this.alertWebhook = alertWebhook;
    }
    /** Check one whole file held in memory. Never throws. */
    async check(file) {
        if (!isHashableImage(file))
            return { status: "skipped", reason: "not_image" };
        let pdq;
        try {
            pdq = await this.hasher(file);
        }
        catch (error) {
            if (error instanceof HasherUnavailable) {
                this.complain(`HASHER UNAVAILABLE, no image is being checked: ${error.message}`);
                return { status: "error", reason: "hasher_unavailable" };
            }
            return {
                status: "error",
                reason: error instanceof TooManyPixels ? "too_many_pixels" : "undecodable",
            };
        }
        if (pdq.quality < MIN_QUALITY)
            return { status: "skipped", reason: "featureless" };
        const hash = pdq.hash.toString("base64");
        const cached = this.cache.get(hash);
        if (cached && cached.expires > Date.now())
            return cached.verdict;
        let verdict;
        try {
            const match = await this.matcher.lookup(pdq.hash);
            verdict = match
                ? { status: "match", hash, provider: this.matcher.name, ...match }
                : { status: "clear", hash };
        }
        catch (error) {
            this.complain(`MATCHER UNAVAILABLE: ${error.message}`);
            return { status: "error", reason: "matcher_unavailable" };
        }
        if (this.cache.size >= CACHE_ENTRIES)
            this.cache.clear();
        this.cache.set(hash, { verdict, expires: Date.now() + CACHE_MS });
        return verdict;
    }
    /**
     * Check a file that is still a stream. An image is read into memory, checked,
     * and handed back as a new stream over the same bytes. Anything that is not
     * read into memory is handed back as the same stream, unread.
     * Rejects only if the stream itself fails or stalls.
     */
    async scanStream(source, size, stage) {
        const stream = source;
        const unread = (verdict) => ({ verdict, stream });
        const { head, ended } = await peek(stream, SNIFF_BYTES);
        if (ended) {
            // Shorter than any image header, and used up by looking.
            return {
                verdict: { status: "skipped", reason: "not_image" },
                stream: Readable.from(head.length !== 0 ? [head] : [], {
                    objectMode: false,
                }),
            };
        }
        if (!isHashableImage(head))
            return unread({ status: "skipped", reason: "not_image" });
        if (size > this.maxBytes)
            return unread({ status: "error", reason: "too_large" });
        // New uploads do not queue without limit: a file that is not checked now
        // is checked before any re-upload.
        if (!(await this.acquire(stage === "store" ? this.maxWaiting : Infinity)))
            return unread({ status: "error", reason: "busy" });
        try {
            const file = await readAll(stream, this.maxBytes, this.readTimeoutMs);
            return {
                verdict: await this.check(file),
                stream: Readable.from([file], { objectMode: false }),
            };
        }
        finally {
            this.release();
        }
    }
    acquire(maxWaiting) {
        if (this.active < this.concurrency) {
            this.active++;
            return Promise.resolve(true);
        }
        if (this.waiting.length >= maxWaiting)
            return Promise.resolve(false);
        return new Promise((resolve) => {
            const waiter = {
                grant: () => {
                    clearTimeout(timer);
                    resolve(true);
                },
            };
            const timer = setTimeout(() => {
                const index = this.waiting.indexOf(waiter);
                if (index !== -1)
                    this.waiting.splice(index, 1);
                resolve(false);
            }, this.maxWaitMs);
            this.waiting.push(waiter);
        });
    }
    release() {
        const next = this.waiting.shift();
        if (next)
            next.grant();
        else
            this.active--;
    }
    /** A loud log line, at most once a minute. */
    complain(message) {
        if (Date.now() - this.lastComplaint < 60000)
            return;
        this.lastComplaint = Date.now();
        console.error(`[FILE SCAN] ${message}`);
    }
    /**
     * Hash a built-in image and make one lookup, and log whether each worked,
     * so a missing native module or wrong credentials show up at start-up
     * rather than as files silently going unchecked.
     */
    async selfTest() {
        try {
            const { hash } = await this.hasher(SELF_TEST_IMAGE);
            await this.matcher.lookup(hash);
            console.log(`[FILE SCAN] on: hashing and ${this.matcher.name} both working`);
            return true;
        }
        catch (error) {
            console.error(`[FILE SCAN] NOT WORKING, images cannot be checked: ${error.message}`);
            return false;
        }
    }
    /**
     * Record a match: a log line, the caller's callback, and the alert webhook.
     * Identifiers and hashes only. Never the file, never a link to it.
     */
    report(detection) {
        const key = `${detection.guild_id}/${detection.channel_id}/${detection.attachment_id}`;
        if (this.reported.has(key))
            return;
        if (this.reported.size >= CACHE_ENTRIES)
            this.reported.clear();
        this.reported.add(key);
        console.warn(`[FILE SCAN] MATCH ${JSON.stringify(detection)}`);
        try {
            this.onDetection?.(detection);
        }
        catch (error) {
            console.error("[FILE SCAN] onDetection failed", error);
        }
        if (this.alertWebhook) {
            this.alert(detection).catch((error) => console.error(`[FILE SCAN] ALERT NOT DELIVERED ${error.message} ${JSON.stringify(detection)}`));
        }
    }
    async alert(detection) {
        const lines = [
            `**File withheld: matched \`${detection.category}\`** (${detection.provider}, ${detection.match_type ?? "unknown"} match)`,
            `Stage: ${detection.stage === "store" ? "before storing (the original may still be on Discord)" : "before re-upload (the stored copy is kept until it expires)"}`,
            `Server \`${detection.guild_id}\` · channel \`${detection.channel_id}\` · attachment \`${detection.attachment_id}\``,
            ...Object.entries(detection.context ?? {}).map(([name, value]) => `${name} \`${value}\``),
            `PDQ \`${detection.pdq}\`${detection.reference ? ` · matched entry \`${detection.reference}\`` : ""}`,
            `Object \`${detection.object}\` · ${detection.time}`,
            "Do not open the file. Follow the abuse and takedown procedure, section 4A.",
        ];
        const body = JSON.stringify({
            content: lines.join("\n"),
            allowed_mentions: { parse: [] },
        });
        let lastError;
        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                const res = await fetch(this.alertWebhook, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body,
                    signal: AbortSignal.timeout(10000),
                });
                if (res.ok)
                    return;
                lastError = new Error(`webhook answered ${res.status}`);
            }
            catch (error) {
                lastError = error;
            }
            await new Promise((resolve) => setTimeout(resolve, 2000 * (attempt + 1)));
        }
        throw lastError;
    }
}
//# sourceMappingURL=scanner.js.map