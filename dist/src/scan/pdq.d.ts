/** sharp or the hash worker could not be loaded: no image can be hashed at all. */
export declare class HasherUnavailable extends Error {
}
/** Decoding the image would take more memory than one check is allowed. */
export declare class TooManyPixels extends Error {
}
export interface PdqResult {
    /** 32 bytes in the order Meta's tools print them (most significant first). */
    hash: Buffer;
    /** 0 to 100. Meta's guidance is to discard hashes with quality under 50. */
    quality: number;
}
/** Frames hashed from an animation when nothing else is said. */
export declare const DEFAULT_MAX_FRAMES = 32;
/** Which frames of an animation to hash: all of them up to `max`, else `max` spread evenly from first to last. */
export declare function framesToHash(pages: number, max: number): number[];
export interface PdqFrames {
    /** One result per hashed frame, in frame order. */
    frames: (PdqResult & {
        frame: number;
    })[];
    /** Frames in the file (1 for a still image). */
    total: number;
}
/**
 * PDQ perceptual hash of an image: the first frame only. Throws
 * HasherUnavailable, TooManyPixels, or the decoder's own error if the image
 * cannot be decoded.
 */
export declare function pdqHash(image: Buffer): Promise<PdqResult>;
/**
 * PDQ hashes of every frame of an animated GIF or WebP, up to `maxFrames`
 * (spread evenly across the animation past that), or of the one frame of a
 * still image. Throws as `pdqHash` does.
 */
export declare function pdqHashFrames(image: Buffer, maxFrames?: number): Promise<PdqFrames>;
