import { createRequire } from "module";
/** sharp or pdq-wasm could not be loaded: no image can be hashed at all. */
export class HasherUnavailable extends Error {
}
/** Decoding the image would take more memory than one check is allowed. */
export class TooManyPixels extends Error {
}
/**
 * Loaded on first use, not at import: sharp is a native module, and a consumer
 * of this package that never scans should not need it to load.
 */
async function load() {
    try {
        const { default: sharp } = await import("sharp");
        // pdq-wasm's ESM build cannot find its own .wasm file under Node; the
        // CommonJS build can.
        const { PDQ } = createRequire(import.meta.url)("pdq-wasm");
        await PDQ.init();
        return { sharp, PDQ };
    }
    catch (error) {
        // Do not remember the failure: the next call tries again.
        loaded = undefined;
        throw new HasherUnavailable(error.message);
    }
}
let loaded;
/**
 * Images up to this many pixels (1920x1080 and below) are hashed at full size,
 * which reproduces Meta's reference hash bit for bit. Larger ones are shrunk
 * to fit 1024x1024 first, which keeps hashing to a few milliseconds and moves
 * the hash by a few bits out of 256 (measured: at most 8 on Meta's test
 * images, against a match threshold of 31).
 */
const FULL_SIZE_PIXELS = 2100000;
const SHRUNK_EDGE = 1024;
/**
 * Peak memory sharp needs to decode one megapixel, in MB, measured per format.
 * JPEG and WebP shrink while decoding; GIF, AVIF and interlaced PNG hold the
 * whole canvas. A small file can declare a huge canvas, so the pixel count is
 * checked before decoding.
 */
const MB_PER_MEGAPIXEL = {
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
const MAX_PIXELS = 268402689;
/**
 * PDQ perceptual hash of an image. Only the first frame of an animation is
 * hashed. Throws HasherUnavailable, TooManyPixels, or the decoder's own error
 * if the image cannot be decoded.
 */
export async function pdqHash(image) {
    const { sharp, PDQ } = await (loaded ?? (loaded = load()));
    const { width = 0, height = 0, format = "", isProgressive,
    // Header only, so safe at any size; the limit is applied just below.
     } = await sharp(image, {
        failOn: "none",
        limitInputPixels: false,
    }).metadata();
    const megapixels = (width * height) / 1e6;
    const cost = format === "png" && isProgressive
        ? INTERLACED_PNG_MB_PER_MEGAPIXEL
        : (MB_PER_MEGAPIXEL[format] ?? MB_PER_MEGAPIXEL.heif);
    if (width * height > MAX_PIXELS || megapixels * cost > DECODE_BUDGET_MB) {
        throw new TooManyPixels(`${format} ${width}x${height}`);
    }
    let pipeline = sharp(image, { failOn: "none", sequentialRead: true })
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
    const result = PDQ.hash({
        data: new Uint8Array(data.buffer, data.byteOffset, data.length),
        width: info.width,
        height: info.height,
        channels: info.channels,
    });
    // pdq-wasm returns the sixteen 16-bit words least significant first. Every
    // other PDQ tool, and every hash database, has them most significant first.
    // Sent unreordered, a hash would never match anything.
    const hash = Buffer.alloc(32);
    for (let word = 0; word < 16; word++) {
        hash[word * 2] = result.hash[(15 - word) * 2];
        hash[word * 2 + 1] = result.hash[(15 - word) * 2 + 1];
    }
    return { hash, quality: result.quality };
}
//# sourceMappingURL=pdq.js.map