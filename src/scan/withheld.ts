/**
 * Why a file was not stored or not handed back for re-upload.
 * `csam` and `harmful-abusive-material` are Arachnid Shield's classifications;
 * any other classification a matcher returns is passed through as-is.
 * `unchecked` means the matcher could not be reached and the file had never
 * passed a check.
 */
export type WithheldReason =
  | "csam"
  | "harmful-abusive-material"
  | "unchecked"
  | (string & {});

/** `upload`: a file sent to the dashboard, refused before it is used. */
export type ScanStage = "store" | "reupload" | "upload";

/** Thrown by downloadFile and fetchFile instead of storing or returning a file. */
export class FileWithheld extends Error {
  reason: WithheldReason;
  stage: ScanStage;

  constructor(reason: WithheldReason, stage: ScanStage) {
    super(`File withheld (${reason}) at ${stage}`);
    this.name = "FileWithheld";
    this.reason = reason;
    this.stage = stage;
  }
}
