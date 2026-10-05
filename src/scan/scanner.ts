import { Readable } from "stream";
import { HasherUnavailable, pdqHash, TooManyPixels } from "./pdq.js";
import type { PdqResult } from "./pdq.js";
import { isHashableImage, SNIFF_BYTES } from "./sniff.js";
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

export type Verdict =
  | { status: "clear"; hash: string }
  | ({ status: "match"; hash: string; provider: string } & Match)
  /** Nothing to check: not an image, or an image with no features to hash. */
  | { status: "skipped"; reason: string }
  /**
   * An image that should have been checked and was not: the matcher or the
   * hasher is unavailable, the scanner is busy, or the image is too large or
   * cannot be decoded.
   */
  | { status: "error"; reason: string };

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

/** A 1x1 PNG. */
const SELF_TEST_IMAGE = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

const CACHE_ENTRIES = 20_000;
const CACHE_MS = 10 * 60 * 1000;
/** Meta's guidance: a PDQ hash with quality under 50 says nothing useful. */
const MIN_QUALITY = 50;

/**
 * The first `bytes` of a stream, put back afterwards so the stream can still
 * be read from the start. `ended` means the whole stream was shorter than
 * that and has been used up.
 */
function peek(
  stream: Readable,
  bytes: number,
): Promise<{ head: Buffer; ended: boolean }> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const cleanup = () => {
      stream.removeListener("readable", onReadable);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
    };
    const onReadable = () => {
      let chunk: Buffer | null;
      while (length < bytes && (chunk = stream.read() as Buffer | null)) {
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
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    stream.on("readable", onReadable);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

/** The whole stream in memory. Gives up past `limit` bytes or `timeoutMs`. */
function readAll(
  stream: Readable,
  limit: number,
  timeoutMs: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let length = 0;
    const cleanup = () => {
      clearTimeout(timer);
      stream.removeListener("data", onData);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
    };
    const abandon = (error: Error) => {
      cleanup();
      // Swallow whatever the stream emits while it is torn down.
      stream.on("error", () => {});
      stream.destroy();
      reject(error);
    };
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      length += chunk.length;
      if (length > limit) abandon(new Error("File is larger than declared"));
    };
    const onEnd = () => {
      cleanup();
      resolve(Buffer.concat(chunks));
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const timer = setTimeout(
      () => abandon(new Error("Timed out reading the file to check it")),
      timeoutMs,
    );
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

export class Scanner {
  matcher: Matcher;
  hasher: (image: Buffer) => Promise<PdqResult>;
  maxBytes: number;
  failClosed: boolean;
  onDetection?: (detection: Detection) => void;
  alertWebhook?: string;
  concurrency: number;
  private maxWaiting: number;
  private maxWaitMs: number;
  private readTimeoutMs: number;
  private active = 0;
  private waiting: { grant: () => void }[] = [];
  private cache = new Map<string, { verdict: Verdict; expires: number }>();
  private reported = new Set<string>();
  private lastComplaint = 0;

  constructor({
    matcher,
    hasher = pdqHash,
    maxBytes = 32 * 1024 * 1024,
    concurrency = 2,
    maxWaiting = 200,
    maxWaitMs = 20_000,
    readTimeoutMs = 30_000,
    failClosed = true,
    onDetection,
    alertWebhook,
  }: {
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
  }) {
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
  async check(file: Buffer): Promise<Verdict> {
    if (!isHashableImage(file))
      return { status: "skipped", reason: "not_image" };

    let pdq;
    try {
      pdq = await this.hasher(file);
    } catch (error) {
      if (error instanceof HasherUnavailable) {
        this.complain(
          `HASHER UNAVAILABLE, no image is being checked: ${error.message}`,
        );
        return { status: "error", reason: "hasher_unavailable" };
      }
      return {
        status: "error",
        reason:
          error instanceof TooManyPixels ? "too_many_pixels" : "undecodable",
      };
    }
    if (pdq.quality < MIN_QUALITY)
      return { status: "skipped", reason: "featureless" };

    const hash = pdq.hash.toString("base64");
    const cached = this.cache.get(hash);
    if (cached && cached.expires > Date.now()) return cached.verdict;

    let verdict: Verdict;
    try {
      const match = await this.matcher.lookup(pdq.hash);
      verdict = match
        ? { status: "match", hash, provider: this.matcher.name, ...match }
        : { status: "clear", hash };
    } catch (error) {
      this.complain(`MATCHER UNAVAILABLE: ${(error as Error).message}`);
      return { status: "error", reason: "matcher_unavailable" };
    }

    if (this.cache.size >= CACHE_ENTRIES) this.cache.clear();
    this.cache.set(hash, { verdict, expires: Date.now() + CACHE_MS });
    return verdict;
  }

  /**
   * Check a file that is still a stream. An image is read into memory, checked,
   * and handed back as a new stream over the same bytes. Anything that is not
   * read into memory is handed back as the same stream, unread.
   * Rejects only if the stream itself fails or stalls.
   */
  async scanStream(
    source: NodeJS.ReadableStream,
    size: number,
    stage: ScanStage,
  ): Promise<{ verdict: Verdict; stream: Readable }> {
    const stream = source as Readable;
    const unread = (verdict: Verdict) => ({ verdict, stream });

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
    } finally {
      this.release();
    }
  }

  private acquire(maxWaiting: number): Promise<boolean> {
    if (this.active < this.concurrency) {
      this.active++;
      return Promise.resolve(true);
    }
    if (this.waiting.length >= maxWaiting) return Promise.resolve(false);
    return new Promise((resolve) => {
      const waiter = {
        grant: () => {
          clearTimeout(timer);
          resolve(true);
        },
      };
      const timer = setTimeout(() => {
        const index = this.waiting.indexOf(waiter);
        if (index !== -1) this.waiting.splice(index, 1);
        resolve(false);
      }, this.maxWaitMs);
      this.waiting.push(waiter);
    });
  }

  private release() {
    const next = this.waiting.shift();
    if (next) next.grant();
    else this.active--;
  }

  /** A loud log line, at most once a minute. */
  private complain(message: string) {
    if (Date.now() - this.lastComplaint < 60_000) return;
    this.lastComplaint = Date.now();
    console.error(`[FILE SCAN] ${message}`);
  }

  /**
   * Hash a built-in image and make one lookup, and log whether each worked,
   * so a missing native module or wrong credentials show up at start-up
   * rather than as files silently going unchecked.
   */
  async selfTest(): Promise<boolean> {
    try {
      const { hash } = await this.hasher(SELF_TEST_IMAGE);
      await this.matcher.lookup(hash);
      console.log(
        `[FILE SCAN] on: hashing and ${this.matcher.name} both working`,
      );
      return true;
    } catch (error) {
      console.error(
        `[FILE SCAN] NOT WORKING, images cannot be checked: ${(error as Error).message}`,
      );
      return false;
    }
  }
  /**
   * Record a match: a log line, the caller's callback, and the alert webhook.
   * Identifiers and hashes only. Never the file, never a link to it.
   */
  report(detection: Detection) {
    const key = `${detection.guild_id}/${detection.channel_id}/${detection.attachment_id}`;
    if (this.reported.has(key)) return;
    if (this.reported.size >= CACHE_ENTRIES) this.reported.clear();
    this.reported.add(key);

    console.warn(`[FILE SCAN] MATCH ${JSON.stringify(detection)}`);
    try {
      this.onDetection?.(detection);
    } catch (error) {
      console.error("[FILE SCAN] onDetection failed", error);
    }
    if (this.alertWebhook) {
      this.alert(detection).catch((error) =>
        console.error(
          `[FILE SCAN] ALERT NOT DELIVERED ${(error as Error).message} ${JSON.stringify(detection)}`,
        ),
      );
    }
  }

  private async alert(detection: Detection) {
    const lines = [
      `**File withheld: matched \`${detection.category}\`** (${detection.provider}, ${detection.match_type ?? "unknown"} match)`,
      `Stage: ${detection.stage === "store" ? "before storing (the original may still be on Discord)" : "before re-upload (the stored copy is kept until it expires)"}`,
      `Server \`${detection.guild_id}\` · channel \`${detection.channel_id}\` · attachment \`${detection.attachment_id}\``,
      ...Object.entries(detection.context ?? {}).map(
        ([name, value]) => `${name} \`${value}\``,
      ),
      `PDQ \`${detection.pdq}\`${detection.reference ? ` · matched entry \`${detection.reference}\`` : ""}`,
      `Object \`${detection.object}\` · ${detection.time}`,
      "Do not open the file. Follow the abuse and takedown procedure, section 4A.",
    ];
    const body = JSON.stringify({
      content: lines.join("\n"),
      allowed_mentions: { parse: [] },
    });
    let lastError: Error | undefined;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await fetch(this.alertWebhook as string, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) return;
        lastError = new Error(`webhook answered ${res.status}`);
      } catch (error) {
        lastError = error as Error;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000 * (attempt + 1)));
    }
    throw lastError;
  }
}
