import { createBrotliCompress, constants } from "node:zlib";
function brotliCompress(size) {
    const params = {
        [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
    };
    if (size !== undefined) {
        params[constants.BROTLI_PARAM_SIZE_HINT] = size;
    }
    return createBrotliCompress({ params });
}
export function compressData(mode, size) {
    switch (mode) {
        case "brotli":
            return brotliCompress(size);
        case "none":
            return new (require("stream").PassThrough)();
        default:
            throw new Error(`Unknown compression mode: ${mode}`);
    }
}
//# sourceMappingURL=compressData.js.map