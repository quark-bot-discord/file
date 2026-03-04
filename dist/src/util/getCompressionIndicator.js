export function getCompressionIndicator(compressionMode) {
    switch (compressionMode) {
        case "brotli":
            return Buffer.from([0x01]);
        case "none":
            return Buffer.from([0x00]);
        default:
            throw new Error(`Unknown compression mode: ${compressionMode}`);
    }
}
//# sourceMappingURL=getCompressionIndicator.js.map