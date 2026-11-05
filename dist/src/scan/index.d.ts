import { Scanner } from "./scanner.js";
import type { Quarantine } from "../quarantine/index.js";
export { ArachnidShieldMatcher } from "./arachnid.js";
export { Scanner } from "./scanner.js";
export type { Detection, DetectionEvidence, Match, Matcher, Verdict, } from "./scanner.js";
export { FileWithheld } from "./withheld.js";
export type { ScanStage, WithheldReason } from "./withheld.js";
export { DEFAULT_MAX_FRAMES, framesToHash, HasherUnavailable, pdqHash, pdqHashFrames, TooManyPixels, } from "./pdq.js";
export type { PdqFrames, PdqResult } from "./pdq.js";
/** True when the environment has Arachnid Shield credentials. */
export declare function scanCredentialsSet(env?: NodeJS.ProcessEnv): boolean;
/**
 * A scanner built from the environment, or undefined when no matcher is
 * configured, in which case nothing is checked and behaviour is unchanged.
 *
 *   ARACHNID_SHIELD_USERNAME, ARACHNID_SHIELD_PASSWORD   turn checking on
 *   ARACHNID_SHIELD_URL          other address for the service
 *   FILE_SCAN_ALERT_WEBHOOK      Discord webhook that receives each detection
 *   FILE_SCAN_FAIL_MODE          `closed` (default) or `open`, see Scanner
 *   FILE_SCAN_MAX_BYTES          largest image checked, in bytes, default 32 MiB
 *   FILE_SCAN_CONCURRENCY        images hashed at once, default 2
 *   FILE_SCAN_MAX_FRAMES         frames of an animation checked, default 32
 *   QUARANTINE_*                 where matches are kept, see quarantineFromEnv
 *
 * With no credentials it logs `[FILE SCAN] NOT WORKING: no credentials` once
 * (when reading process.env) and returns undefined.
 */
export declare function scannerFromEnv(env?: NodeJS.ProcessEnv, { quarantine, }?: {
    quarantine?: Quarantine;
}): Scanner | undefined;
