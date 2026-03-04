import { PassThrough } from "stream";
export type CompressionMode = "brotli" | "none";
export declare function compressData(mode: CompressionMode, size?: number): PassThrough;
