import { createBrotliCompress, constants, BrotliCompress } from "node:zlib";

export type CompressionMode = "brotli" | "none";

function brotliCompress(size?: number): BrotliCompress {
    const params: { [key: number]: number | boolean } = {
        [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
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
            return new (require("stream").PassThrough)();
        default:
            throw new Error(`Unknown compression mode: ${mode}`);
    }
}