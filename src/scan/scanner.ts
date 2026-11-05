import { Readable } from "stream";
import {
  DEFAULT_MAX_FRAMES,
  HasherUnavailable,
  pdqHashFrames,
  TooManyPixels,
} from "./pdq.js";
import type { PdqFrames, PdqResult } from "./pdq.js";
import type { Quarantine, QuarantineSubject } from "../quarantine/index.js";
import { isHashableImage, SNIFF_BYTES } from "./sniff.js";
import type { ScanStage } from "./withheld.js";

export interface Match {
  /** The matcher's classification, e.g. `csam`. */
  category: string;
  /** `exact`, `near`, or null if the matcher does not say. */
  matchType: string | null;
  /** The matcher's identifier for the database entry that matched, if any. */
  reference?: string;
  /** The matcher's answer for this hash, as it gave it: the basis for a report. */
  details?: unknown;
}

/** A service that answers "is this hash known?". It is only ever given a hash. */
export interface Matcher {
  name: string;
  lookup(hash: Buffer): Promise<Match | null>;
}

export type Verdict =
  | {
      status: "clear";
      /** Base64 PDQ hash of the first frame. */
      hash: string;
      /** Every frame's hash that was looked up, base64. */
      hashes?: string[];
      /** Frames in the file, and how many were hashed. */
      frames?: { total: number; checked: number };
    }
  | ({
      status: "match";
      /** Base64 PDQ hash of the frame that matched. */
      hash: string;
      provider: string;
      /** Which frame matched (0 for a still image). */
      frame?: number;
      hashes?: string[];
      frames?: { total: number; checked: number };
    } & Match)
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
  frames?: { total: number; checked: number };
  /** The matcher's identifier for the database entry that matched. */
  reference?: string;
  /** The matcher's answer, as it gave it. Kept in quarantine, not alerted. */
  match_details?: unknown;
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
  frameHasher: (image: Buffer, maxFrames: number) => Promise<PdqFrames>;
  maxFrames: number;
  quarantine?: Quarantine;
  maxBytes: number;
  failClosed: boolean;
  onDetection?: (detection: Detection) => void;
  onQuarantined?: (id: string, detection: Detection) => void;
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
    hasher,
    frameHasher,
    maxFrames = DEFAULT_MAX_FRAMES,
    quarantine,
    maxBytes = 32 * 1024 * 1024,
    concurrency = 2,
    maxWaiting = 200,
    maxWaitMs = 20_000,
    readTimeoutMs = 30_000,
    failClosed = true,
    onDetection,
    onQuarantined,
    alertWebhook,
  }: {
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
    /**
     * Called once a match is in quarantine, e.g. to have the website add
     * what it holds about the person to the same item.
     */
    onQuarantined?: (id: string, detection: Detection) => void;
    /** Discord webhook URL that receives one message per detection. */
    alertWebhook?: string;
  }) {
    this.matcher = matcher;
    this.frameHasher =
      frameHasher ??
      (hasher
        ? async (image: Buffer) => ({
            frames: [{ ...(await hasher(image)), frame: 0 }],
            total: 1,
          })
        : pdqHashFrames);
    this.hasher =
      hasher ??
      (async (image: Buffer) =>
        (await this.frameHasher(image, 1)).frames[0]);
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
  async check(file: Buffer): Promise<Verdict> {
    if (!isHashableImage(file))
      return { status: "skipped", reason: "not_image" };

    let pdq: PdqFrames;
    try {
      pdq = await this.frameHasher(file, this.maxFrames);
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
    const usable = pdq.frames.filter((f) => f.quality >= MIN_QUALITY);
    if (usable.length === 0)
      return { status: "skipped", reason: "featureless" };

    const frames = { total: pdq.total, checked: pdq.frames.length };
    const hashes = [...new Set(usable.map((f) => f.hash.toString("base64")))];

    let results: Verdict[];
    try {
      results = await Promise.all(
        hashes.map((hash) => this.lookupOne(Buffer.from(hash, "base64"))),
      );
    } catch (error) {
      this.complain(`MATCHER UNAVAILABLE: ${(error as Error).message}`);
      return { status: "error", reason: "matcher_unavailable" };
    }

    const matched = results.findIndex((r) => r.status === "match");
    if (matched !== -1) {
      const verdict = results[matched] as Extract<Verdict, { status: "match" }>;
      const frame = usable.find(
        (f) => f.hash.toString("base64") === verdict.hash,
      )?.frame;
      return { ...verdict, frame, hashes, frames };
    }
    return { status: "clear", hash: hashes[0], hashes, frames };
  }

  /** One hash looked up, through the cache. Throws if the matcher fails. */
  private async lookupOne(hash: Buffer): Promise<Verdict> {
    const key = hash.toString("base64");
    const cached = this.cache.get(key);
    if (cached && cached.expires > Date.now()) return cached.verdict;
    const match = await this.matcher.lookup(hash);
    const verdict: Verdict = match
      ? { status: "match", hash: key, provider: this.matcher.name, ...match }
      : { status: "clear", hash: key };
    if (this.cache.size >= CACHE_ENTRIES) this.cache.clear();
    this.cache.set(key, { verdict, expires: Date.now() + CACHE_MS });
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
  ): Promise<{ verdict: Verdict; stream: Readable; file?: Buffer }> {
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
        file,
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
    if (!this.quarantine)
      console.error(
        "[FILE SCAN] QUARANTINE NOT CONFIGURED (QUARANTINE_BUCKET, QUARANTINE_KEY): matches are withheld and alerted but not kept for a report",
      );
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
   * Record a match: a log line, the quarantine, the caller's callback, and the
   * alert webhook. The alert carries identifiers and hashes only: never the
   * file, a link to it, or anything about the person beyond their id.
   *
   * Resolves with the quarantine id, or undefined when nothing was kept
   * (no quarantine configured, a repeat, or the write failed: each logged).
   * Never rejects.
   */
  async report(
    detection: Detection,
    evidence: DetectionEvidence = {},
  ): Promise<string | undefined> {
    const key = detection.attachment_id
      ? `${detection.guild_id}/${detection.channel_id}/${detection.attachment_id}`
      : `${detection.source}/${detection.guild_id}/${detection.user_id}/${detection.pdq}`;
    if (this.reported.has(key)) {
      console.warn(`[FILE SCAN] MATCH (repeat) ${JSON.stringify(detection)}`);
      return undefined;
    }
    if (this.reported.size >= CACHE_ENTRIES) this.reported.clear();
    this.reported.add(key);

    console.warn(`[FILE SCAN] MATCH ${JSON.stringify(detection)}`);

    let quarantined: { id?: string; problem?: string } = {};
    if (!this.quarantine) {
      quarantined = { problem: "no quarantine store is configured" };
    } else if (!evidence.content) {
      quarantined = { problem: "the file was not in hand to keep" };
    } else {
      try {
        let relevant: unknown;
        let relevantError: string | undefined;
        try {
          relevant = await evidence.relevantData?.();
        } catch (error) {
          relevantError = (error as Error).message;
        }
        quarantined.id = await this.quarantine.put({
          detection,
          content: evidence.content,
          contentType: evidence.contentType,
          fileName: evidence.fileName,
          subject: evidence.subject ?? {
            user_id: detection.user_id ?? detection.context?.user_id,
            guild_id: detection.guild_id,
            channel_id: detection.channel_id,
            message_id: detection.context?.message_id,
            attachment_id: detection.attachment_id,
          },
          relevantData: relevant,
          relevantDataError: relevantError,
        });
        try {
          this.onQuarantined?.(quarantined.id, detection);
        } catch (error) {
          console.error("[FILE SCAN] onQuarantined failed", error);
        }
      } catch (error) {
        quarantined.problem = `the quarantine write failed: ${(error as Error).message}`;
        console.error(
          `[FILE SCAN] NOT QUARANTINED ${quarantined.problem} ${JSON.stringify(detection)}`,
        );
      }
    }

    try {
      this.onDetection?.(detection);
    } catch (error) {
      console.error("[FILE SCAN] onDetection failed", error);
    }
    if (this.alertWebhook) {
      await this.alert(detection, quarantined).catch((error) =>
        console.error(
          `[FILE SCAN] ALERT NOT DELIVERED ${(error as Error).message} ${JSON.stringify(detection)}`,
        ),
      );
    } else {
      console.error(
        `[FILE SCAN] NO ALERT WEBHOOK (FILE_SCAN_ALERT_WEBHOOK) for ${JSON.stringify(detection)}`,
      );
    }
    return quarantined.id;
  }

  private async alert(
    detection: Detection,
    quarantined: { id?: string; problem?: string },
  ) {
    const stage =
      detection.stage === "store"
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
      ...Object.entries(detection.context ?? {}).map(
        ([name, value]) => `${name} \`${value}\``,
      ),
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
