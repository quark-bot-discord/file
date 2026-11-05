import { ArachnidShieldMatcher } from "./arachnid.js";
import { Scanner } from "./scanner.js";
import { quarantineFromEnv } from "../quarantine/index.js";
import type { Quarantine } from "../quarantine/index.js";

export { ArachnidShieldMatcher } from "./arachnid.js";
export { Scanner } from "./scanner.js";
export type {
  Detection,
  DetectionEvidence,
  Match,
  Matcher,
  Verdict,
} from "./scanner.js";
export { FileWithheld } from "./withheld.js";
export type { ScanStage, WithheldReason } from "./withheld.js";
export {
  DEFAULT_MAX_FRAMES,
  framesToHash,
  HasherUnavailable,
  pdqHash,
  pdqHashFrames,
  TooManyPixels,
} from "./pdq.js";
export type { PdqFrames, PdqResult } from "./pdq.js";

/** True when the environment has Arachnid Shield credentials. */
export function scanCredentialsSet(env: NodeJS.ProcessEnv = process.env) {
  return Boolean(env.ARACHNID_SHIELD_USERNAME && env.ARACHNID_SHIELD_PASSWORD);
}

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
export function scannerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  {
    quarantine = quarantineFromEnv(env),
    app = env.APM_SERVICE_NAME || env.OTEL_SERVICE_NAME || "this process",
  }: {
    quarantine?: Quarantine;
    /** Named in the start-up line, e.g. "serverlog" or "website". */
    app?: string;
  } = {},
): Scanner | undefined {
  const username = env.ARACHNID_SHIELD_USERNAME;
  const password = env.ARACHNID_SHIELD_PASSWORD;
  if (!username || !password) {
    if (env === process.env && !warnedNoCredentials) {
      warnedNoCredentials = true;
      console.error(`[FILE SCAN] NOT WORKING: no credentials (${app})`);
    }
    return undefined;
  }

  /** A positive number from the environment, or undefined (use the default). */
  const positive = (name: string) => {
    const raw = env[name];
    if (!raw) return undefined;
    const value = Number(raw);
    if (Number.isFinite(value) && value > 0) return value;
    console.error(`[FILE SCAN] ignoring ${name}=${raw}: not a positive number`);
    return undefined;
  };

  const scanner = new Scanner({
    matcher: new ArachnidShieldMatcher({
      username,
      password,
      baseUrl: env.ARACHNID_SHIELD_URL || undefined,
    }),
    alertWebhook: env.FILE_SCAN_ALERT_WEBHOOK || undefined,
    failClosed: env.FILE_SCAN_FAIL_MODE !== "open",
    maxBytes: positive("FILE_SCAN_MAX_BYTES"),
    concurrency: positive("FILE_SCAN_CONCURRENCY"),
    maxFrames: positive("FILE_SCAN_MAX_FRAMES"),
    quarantine,
  });
  if (env === process.env) void scanner.selfTest(app);
  return scanner;
}

let warnedNoCredentials = false;
