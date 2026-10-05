import { Scanner } from "./scanner.js";
export { ArachnidShieldMatcher } from "./arachnid.js";
export { Scanner } from "./scanner.js";
export type { Detection, Match, Matcher, Verdict } from "./scanner.js";
export { FileWithheld } from "./withheld.js";
export type { ScanStage, WithheldReason } from "./withheld.js";
export { HasherUnavailable, pdqHash, TooManyPixels } from "./pdq.js";
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
 */
export declare function scannerFromEnv(env?: NodeJS.ProcessEnv): Scanner | undefined;
