/**
 * True when the first bytes are a format the hasher can decode. The decision
 * is made on content, not on the file name or the content type the uploader
 * chose, so renaming an image does not skip the check.
 */
export declare function isHashableImage(head: Buffer): boolean;
/** Bytes of the file needed before `isHashableImage` can answer. */
export declare const SNIFF_BYTES = 12;
