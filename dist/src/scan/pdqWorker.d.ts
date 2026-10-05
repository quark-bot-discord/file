export interface HashRequest {
    id: number;
    pixels: ArrayBuffer;
    width: number;
    height: number;
    channels: number;
}
export type HashReply = {
    id: number;
    hash: Uint8Array;
    quality: number;
} | {
    id: number;
    error: string;
    unavailable: boolean;
};
