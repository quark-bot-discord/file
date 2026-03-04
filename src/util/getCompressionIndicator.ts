import { CompressionMode } from "../core/compressData.js";

export function getCompressionIndicator(compressionMode: CompressionMode): Uint8Array {
  switch (compressionMode) {
    case "brotli":
      return Buffer.from([0x01]);
    case "none":
      return Buffer.from([0x00]);
    default:
      throw new Error(`Unknown compression mode: ${compressionMode}`);
  }
}