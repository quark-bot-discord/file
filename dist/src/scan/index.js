import { ArachnidShieldMatcher } from "./arachnid.js";
import { Scanner } from "./scanner.js";
export { ArachnidShieldMatcher } from "./arachnid.js";
export { Scanner } from "./scanner.js";
export { FileWithheld } from "./withheld.js";
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
export function scannerFromEnv(env = process.env) {
    const username = env.ARACHNID_SHIELD_USERNAME;
    const password = env.ARACHNID_SHIELD_PASSWORD;
    if (!username || !password)
        return undefined;
    /** A positive number from the environment, or undefined (use the default). */
    const positive = (name) => {
        const raw = env[name];
        if (!raw)
            return undefined;
        const value = Number(raw);
        if (Number.isFinite(value) && value > 0)
            return value;
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
    });
    if (env === process.env)
        void scanner.selfTest();
    return scanner;
}
//# sourceMappingURL=index.js.map