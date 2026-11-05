import { Worker } from "worker_threads";
import type { HashReply, HashRequest } from "./pdqWorker.js";

/** sharp or the hash worker could not be loaded: no image can be hashed at all. */
export class HasherUnavailable extends Error {}

/** Decoding the image would take more memory than one check is allowed. */
export class TooManyPixels extends Error {}

/**
 * Loaded on first use, not at import: sharp is a native module, and a consumer
 * of this package that never scans should not need it to load.
 */
async function load() {
  try {
    return (await import("sharp")).default;
  } catch (error) {
    // Do not remember the failure: the next call tries again.
    loaded = undefined;
    throw new HasherUnavailable((error as Error).message);
  }
}

let loaded: ReturnType<typeof load> | undefined;

let worker: Worker | undefined;
let nextId = 0;
const pending = new Map<
  number,
  {
    resolve: (result: { hash: Uint8Array; quality: number }) => void;
    reject: (error: Error) => void;
  }
>();

/** Hash raw pixels on the worker thread, starting it if needed. */
function hashPixels(
  pixels: Uint8Array,
  width: number,
  height: number,
  channels: number,
): Promise<{ hash: Uint8Array; quality: number }> {
  if (!worker) {
    const started = new Worker(new URL("./pdqWorker.js", import.meta.url));
    const lost = (error: Error) => {
      if (worker === started) worker = undefined;
      for (const waiting of pending.values())
        waiting.reject(new HasherUnavailable(error.message));
      pending.clear();
    };
    started.on("message", (reply: HashReply) => {
      const waiting = pending.get(reply.id);
      if (!waiting) return;
      pending.delete(reply.id);
      // An idle worker should not keep the process alive.
      if (pending.size === 0) started.unref();
      if ("error" in reply) {
        waiting.reject(
          reply.unavailable
            ? new HasherUnavailable(reply.error)
            : new Error(reply.error),
        );
      } else waiting.resolve(reply);
    });
    started.on("error", lost);
    started.on("exit", () => lost(new Error("hash worker exited")));
    worker = started;
  }
  const id = nextId++;
  // A copy the worker can take ownership of.
  const copy = new Uint8Array(pixels);
  const request: HashRequest = {
    id,
    pixels: copy.buffer,
    width,
    height,
    channels,
  };
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    (worker as Worker).ref();
    (worker as Worker).postMessage(request, [copy.buffer]);
  });
}

/**
 * Images up to this many pixels (1920x1080 and below) are hashed at full size,
 * which reproduces Meta's reference hash bit for bit. Larger ones are shrunk
 * to fit 1024x1024 first, which bounds the time and memory one hash takes and
 * moves the hash by a few bits out of 256 (measured: at most 8 on Meta's test
 * images, against a match threshold of 31).
 */
const FULL_SIZE_PIXELS = 2_100_000;
const SHRUNK_EDGE = 1024;

/**
 * Peak memory sharp needs to decode one megapixel, in MB, measured per format.
 * JPEG and WebP shrink while decoding; GIF, AVIF and interlaced PNG hold the
 * whole canvas. A small file can declare a huge canvas, so the pixel count is
 * checked before decoding.
 */
const MB_PER_MEGAPIXEL: Record<string, number> = {
  jpeg: 0.1,
  webp: 0.1,
  png: 0.7,
  tiff: 0.7,
  gif: 5,
  heif: 17,
};
const INTERLACED_PNG_MB_PER_MEGAPIXEL = 3.5;
const DECODE_BUDGET_MB = 150;
/** libvips' own ceiling, which applies whatever the format. */
const MAX_PIXELS = 268_402_689;

export interface PdqResult {
  /** 32 bytes in the order Meta's tools print them (most significant first). */
  hash: Buffer;
  /** 0 to 100. Meta's guidance is to discard hashes with quality under 50. */
  quality: number;
}

/** Frames hashed from an animation when nothing else is said. */
export const DEFAULT_MAX_FRAMES = 32;

/** Which frames of an animation to hash: all of them up to `max`, else `max` spread evenly from first to last. */
export function framesToHash(pages: number, max: number): number[] {
  const count = Math.max(1, Math.floor(pages));
  const cap = Math.max(1, Math.floor(max));
  if (count <= cap) return [...Array(count).keys()];
  if (cap === 1) return [0];
  const chosen = new Set<number>();
  for (let i = 0; i < cap; i++)
    chosen.add(Math.round((i * (count - 1)) / (cap - 1)));
  return [...chosen].sort((a, b) => a - b);
}

export interface PdqFrames {
  /** One result per hashed frame, in frame order. */
  frames: (PdqResult & { frame: number })[];
  /** Frames in the file (1 for a still image). */
  total: number;
}

/**
 * PDQ perceptual hash of an image: the first frame only. Throws
 * HasherUnavailable, TooManyPixels, or the decoder's own error if the image
 * cannot be decoded.
 */
export async function pdqHash(image: Buffer): Promise<PdqResult> {
  const { frames } = await pdqHashFrames(image, 1);
  return frames[0];
}

/**
 * PDQ hashes of every frame of an animated GIF or WebP, up to `maxFrames`
 * (spread evenly across the animation past that), or of the one frame of a
 * still image. Throws as `pdqHash` does.
 */
export async function pdqHashFrames(
  image: Buffer,
  maxFrames: number = DEFAULT_MAX_FRAMES,
): Promise<PdqFrames> {
  const sharp = await (loaded ??= load());

  const {
    width = 0,
    height = 0,
    format = "",
    isProgressive,
    pages = 1,
    // Header only, so safe at any size; the limit is applied just below.
  } = await sharp(image, {
    failOn: "none",
    limitInputPixels: false,
  }).metadata();

  // `height` is one frame's: each frame is decoded on its own below.
  const megapixels = (width * height) / 1e6;
  const cost =
    format === "png" && isProgressive
      ? INTERLACED_PNG_MB_PER_MEGAPIXEL
      : (MB_PER_MEGAPIXEL[format] ?? MB_PER_MEGAPIXEL.heif);
  if (width * height > MAX_PIXELS || megapixels * cost > DECODE_BUDGET_MB) {
    throw new TooManyPixels(`${format} ${width}x${height}`);
  }

  const animated = pages > 1 && (format === "gif" || format === "webp");
  const chosen = animated ? framesToHash(pages, maxFrames) : [0];

  const frames: PdqFrames["frames"] = [];
  for (const frame of chosen) {
    let pipeline = sharp(image, {
      failOn: "none",
      sequentialRead: true,
      ...(animated ? { page: frame, pages: 1 } : {}),
    })
      .removeAlpha()
      .toColourspace("srgb");
    if (width * height > FULL_SIZE_PIXELS) {
      pipeline = pipeline.resize(SHRUNK_EDGE, SHRUNK_EDGE, {
        fit: "inside",
        withoutEnlargement: true,
      });
    }
    const { data, info } = await pipeline
      .raw()
      .toBuffer({ resolveWithObject: true });

    const result = await hashPixels(
      data,
      info.width,
      info.height,
      info.channels,
    );

    // pdq-wasm returns the sixteen 16-bit words least significant first.
    // Every other PDQ tool, and every hash database, has them most
    // significant first. Sent unreordered, a hash would never match anything.
    const hash = Buffer.alloc(32);
    for (let word = 0; word < 16; word++) {
      hash[word * 2] = result.hash[(15 - word) * 2];
      hash[word * 2 + 1] = result.hash[(15 - word) * 2 + 1];
    }
    frames.push({ hash, quality: result.quality, frame });
  }
  return { frames, total: animated ? pages : 1 };
}
