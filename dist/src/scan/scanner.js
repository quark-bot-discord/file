import { Readable } from "stream";
import { DEFAULT_MAX_FRAMES, HasherUnavailable, pdqHashFrames, TooManyPixels, } from "./pdq.js";
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
/**
 * Who sent it: the caller's subject over what the detection says, with the
 * server's name from the relevant data when the caller only had it there.
 */
function subjectOf(detection, given, relevant) {
    const subject = {
        user_id: detection.user_id ?? detection.context?.user_id,
        guild_id: detection.guild_id,
        channel_id: detection.channel_id,
        message_id: detection.context?.message_id,
        attachment_id: detection.attachment_id,
    };
    for (const [key, value] of Object.entries(given ?? {}))
        if (value !== undefined && value !== null)
            subject[key] = value;
    const guildName = relevant
        ?.guild?.name;
    if (!subject.guild_name && typeof guildName === "string")
        subject.guild_name = guildName;
    return subject;
}
export class Scanner {
    constructor({ matcher, hasher, frameHasher, maxFrames = DEFAULT_MAX_FRAMES, quarantine, maxBytes = 32 * 1024 * 1024, concurrency = 2, maxWaiting = 200, maxWaitMs = 20000, readTimeoutMs = 30000, failClosed = true, onDetection, onQuarantined, alertWebhook, }) {
        this.active = 0;
        this.waiting = [];
        this.cache = new Map();
        this.reported = new Set();
        this.lastComplaint = 0;
        this.matcher = matcher;
        this.frameHasher =
            frameHasher ??
                (hasher
                    ? async (image) => ({
                        frames: [{ ...(await hasher(image)), frame: 0 }],
                        total: 1,
                    })
                    : pdqHashFrames);
        this.hasher =
            hasher ??
                (async (image) => (await this.frameHasher(image, 1)).frames[0]);
        this.maxFrames = maxFrames;
        this.quarantine = quarantine;
        this.maxBytes = maxBytes;
        this.concurrency = concurrency;
        this.maxWaiting = maxWaiting;
        this.maxWaitMs = maxWaitMs;
        this.readTimeoutMs = readTimeoutMs;
        this.failClosed = failClosed;
        this.onDetection = onDetection;
        this.onQuarantined = onQuarantined;
        this.alertWebhook = alertWebhook;
    }
    /**
     * Check one whole file held in memory. Every frame of an animation is
     * checked, up to `maxFrames`. Never throws.
     */
    async check(file) {
        if (!isHashableImage(file))
            return { status: "skipped", reason: "not_image" };
        let pdq;
        try {
            pdq = await this.frameHasher(file, this.maxFrames);
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
        const usable = pdq.frames.filter((f) => f.quality >= MIN_QUALITY);
        if (usable.length === 0)
            return { status: "skipped", reason: "featureless" };
        const frames = { total: pdq.total, checked: pdq.frames.length };
        const hashes = [...new Set(usable.map((f) => f.hash.toString("base64")))];
        let results;
        try {
            results = await Promise.all(hashes.map((hash) => this.lookupOne(Buffer.from(hash, "base64"))));
        }
        catch (error) {
            this.complain(`MATCHER UNAVAILABLE: ${error.message}`);
            return { status: "error", reason: "matcher_unavailable" };
        }
        const matched = results.findIndex((r) => r.status === "match");
        if (matched !== -1) {
            const verdict = results[matched];
            const frame = usable.find((f) => f.hash.toString("base64") === verdict.hash)?.frame;
            return { ...verdict, frame, hashes, frames };
        }
        return { status: "clear", hash: hashes[0], hashes, frames };
    }
    /** One hash looked up, through the cache. Throws if the matcher fails. */
    async lookupOne(hash) {
        const key = hash.toString("base64");
        const cached = this.cache.get(key);
        if (cached && cached.expires > Date.now())
            return cached.verdict;
        const match = await this.matcher.lookup(hash);
        const verdict = match
            ? { status: "match", hash: key, provider: this.matcher.name, ...match }
            : { status: "clear", hash: key };
        if (this.cache.size >= CACHE_ENTRIES)
            this.cache.clear();
        this.cache.set(key, { verdict, expires: Date.now() + CACHE_MS });
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
                file,
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
    /**
     * Say why a file that never passed a check is being withheld because this
     * check could not run either (at most once a minute, like the others).
     */
    noteUnchecked(reason) {
        this.complain(`WITHHELD UNCHECKED: the check could not run (${reason})`);
    }
    /** A loud log line, at most once a minute. */
    complain(message) {
        if (Date.now() - this.lastComplaint < 60000)
            return;
        this.lastComplaint = Date.now();
        console.error(`[FILE SCAN] ${message}`);
    }
    /**
     * Hash a built-in image and make one authenticated lookup with it, and log
     * one line saying whether the check is live, so a missing native module or
     * refused credentials show up at start-up rather than as files silently
     * going unchecked. The lookup is the authenticated call (Arachnid Shield
     * answers 401 to wrong credentials); the image is a 1x1 PNG.
     */
    async selfTest(app = "this process") {
        if (!this.quarantine)
            console.error("[FILE SCAN] QUARANTINE NOT CONFIGURED (QUARANTINE_BUCKET, QUARANTINE_KEY): matches are withheld and alerted but not kept for a report");
        try {
            const { hash } = await this.hasher(SELF_TEST_IMAGE);
            await this.matcher.lookup(hash);
            console.log(`[FILE SCAN] LIVE in ${app}: hashing works and ${this.matcher.name} accepted the credentials${this.quarantine ? "; quarantine configured" : ""}`);
            return true;
        }
        catch (error) {
            console.error(`[FILE SCAN] NOT LIVE in ${app}, images cannot be checked: ${error.message}`);
            return false;
        }
    }
    /**
     * Record a match: a log line, the quarantine, the caller's callback, and the
     * alert webhook. The alert carries identifiers and hashes only: never the
     * file, a link to it, or anything about the person beyond their id.
     *
     * Resolves with the quarantine id, or undefined when nothing was kept
     * (no quarantine configured, a repeat, or the write failed: each logged).
     * Never rejects.
     */
    async report(detection, evidence = {}) {
        const key = detection.attachment_id
            ? `${detection.guild_id}/${detection.channel_id}/${detection.attachment_id}`
            : `${detection.source}/${detection.guild_id}/${detection.user_id}/${detection.pdq}`;
        if (this.reported.has(key)) {
            console.warn(`[FILE SCAN] MATCH (repeat) ${JSON.stringify(detection)}`);
            return undefined;
        }
        if (this.reported.size >= CACHE_ENTRIES)
            this.reported.clear();
        this.reported.add(key);
        console.warn(`[FILE SCAN] MATCH ${JSON.stringify(detection)}`);
        let quarantined = {};
        if (!this.quarantine) {
            quarantined = { problem: "no quarantine store is configured" };
        }
        else if (!evidence.content) {
            quarantined = { problem: "the file was not in hand to keep" };
        }
        else {
            try {
                let relevant;
                let relevantError;
                try {
                    relevant = await evidence.relevantData?.();
                }
                catch (error) {
                    relevantError = error.message;
                }
                quarantined.id = await this.quarantine.put({
                    detection,
                    content: evidence.content,
                    contentType: evidence.contentType,
                    fileName: evidence.fileName,
                    subject: subjectOf(detection, evidence.subject, relevant),
                    relevantData: relevant,
                    relevantDataError: relevantError,
                });
                try {
                    this.onQuarantined?.(quarantined.id, detection);
                }
                catch (error) {
                    console.error("[FILE SCAN] onQuarantined failed", error);
                }
            }
            catch (error) {
                quarantined.problem = `the quarantine write failed: ${error.message}`;
                console.error(`[FILE SCAN] NOT QUARANTINED ${quarantined.problem} ${JSON.stringify(detection)}`);
            }
        }
        try {
            this.onDetection?.(detection);
        }
        catch (error) {
            console.error("[FILE SCAN] onDetection failed", error);
        }
        if (this.alertWebhook) {
            await this.alert(detection, quarantined).catch((error) => console.error(`[FILE SCAN] ALERT NOT DELIVERED ${error.message} ${JSON.stringify(detection)}`));
        }
        else {
            console.error(`[FILE SCAN] NO ALERT WEBHOOK (FILE_SCAN_ALERT_WEBHOOK) for ${JSON.stringify(detection)}`);
        }
        return quarantined.id;
    }
    async alert(detection, quarantined) {
        const stage = detection.stage === "store"
            ? "before storing (the original may still be on Discord)"
            : detection.stage === "reupload"
                ? "before re-upload (the stored copy is kept until it expires)"
                : `refused at upload on the dashboard${detection.route ? ` (${detection.route})` : ""}`;
        const where = [
            `Server \`${detection.guild_id}\``,
            detection.channel_id && `channel \`${detection.channel_id}\``,
            detection.attachment_id && `attachment \`${detection.attachment_id}\``,
            detection.user_id && `user \`${detection.user_id}\``,
        ].filter(Boolean);
        const lines = [
            `**${detection.stage === "upload" ? "Upload refused" : "File withheld"}: matched \`${detection.category}\`** (${detection.provider}, ${detection.match_type ?? "unknown"} match${detection.frame ? `, frame ${detection.frame}` : ""})`,
            `Stage: ${stage}`,
            where.join(" · "),
            ...Object.entries(detection.context ?? {}).map(([name, value]) => `${name} \`${value}\``),
            `PDQ \`${detection.pdq}\`${detection.reference ? ` · matched entry \`${detection.reference}\`` : ""}`,
            `${detection.object ? `Object \`${detection.object}\` · ` : ""}${detection.time}`,
            quarantined.id
                ? `Quarantined as \`${quarantined.id}\`: prepare the NCA report from /admin/safety.`
                : `**NOT QUARANTINED**: ${quarantined.problem ?? "unknown"}.`,
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