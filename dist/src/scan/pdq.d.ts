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
/**
 * PDQ perceptual hash of an image. Only the first frame of an animation is
 * hashed. Throws HasherUnavailable, TooManyPixels, or the decoder's own error
 * if the image cannot be decoded.
 */
export declare function pdqHash(image: Buffer): Promise<PdqResult>;
