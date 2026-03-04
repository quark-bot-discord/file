import { createBrotliCompress, constants, BrotliCompress } from "node:zlib";
import { PassThrough } from "stream";

export type CompressionMode = "brotli" | "none";

function brotliCompress(size?: number): BrotliCompress {
    const params: { [key: number]: number | boolean } = {
        [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MIN_QUALITY,
    };
    if (size !== undefined) {
        params[constants.BROTLI_PARAM_SIZE_HINT] = size;
    }
    return createBrotliCompress({ params });
}

export function compressData(mode: CompressionMode, size?: number) {
    switch (mode) {
        case "brotli":
            return brotliCompress(size);
        case "none":
            return new PassThrough();
        default:
            throw new Error(`Unknown compression mode: ${mode}`);
    }
}