/** The address in Arachnid Shield's own client. */
const DEFAULT_BASE_URL = "https://shield.projectarachnid.ca/";
const NO_MATCH = "no-known-match";
/**
 * Looks PDQ hashes up in Project Arachnid Shield (Canadian Centre for Child
 * Protection). Only the hash is sent: `POST /v1/pdq/` with
 * `{ "hashes": [<base64>, ...] }`. The file never leaves this process.
 *
 * Lookups made within `batchWindowMs` of each other share one request.
 */
export class ArachnidShieldMatcher {
    constructor({ username, password, baseUrl = DEFAULT_BASE_URL, timeoutMs = 8000, batchWindowMs = 25, batchSize = 100, }) {
        this.name = "arachnid-shield";
        this.queue = new Map();
        this.url = new URL("/v1/pdq/", baseUrl).toString();
        this.authorization =
            "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
        this.timeoutMs = timeoutMs;
        this.batchWindowMs = batchWindowMs;
        this.batchSize = batchSize;
    }
    lookup(hash) {
        const key = hash.toString("base64");
        return new Promise((resolve, reject) => {
            const waiting = this.queue.get(key);
            if (waiting)
                waiting.push({ resolve, reject });
            else
                this.queue.set(key, [{ resolve, reject }]);
            if (this.queue.size >= this.batchSize)
                this.flush();
            else
                this.timer ?? (this.timer = setTimeout(() => this.flush(), this.batchWindowMs));
        });
    }
    flush() {
        clearTimeout(this.timer);
        this.timer = undefined;
        const batch = this.queue;
        this.queue = new Map();
        if (batch.size === 0)
            return;
        this.send([...batch.keys()]).then((scanned) => {
            for (const [hash, waiting] of batch) {
                const entry = scanned[hash];
                // A hash the service did not answer for has not been checked.
                if (!entry || typeof entry.classification !== "string") {
                    const error = new Error("Arachnid Shield returned no result");
                    waiting.forEach((w) => w.reject(error));
                    continue;
                }
                const match = entry.classification === NO_MATCH
                    ? null
                    : {
                        category: entry.classification,
                        matchType: entry.match_type ?? null,
                        reference: entry.near_match_details?.sha256_hex,
                        details: entry,
                    };
                waiting.forEach((w) => w.resolve(match));
            }
        }, (error) => {
            for (const waiting of batch.values())
                waiting.forEach((w) => w.reject(error));
        });
    }
    async send(hashes) {
        const res = await fetch(this.url, {
            method: "POST",
            headers: {
                Authorization: this.authorization,
                "Content-Type": "application/json; charset=utf-8",
            },
            body: JSON.stringify({ hashes }),
            signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (!res.ok)
            throw new Error(`Arachnid Shield answered ${res.status}`);
        const body = (await res.json());
        if (!body ||
            typeof body.scanned_hashes !== "object" ||
            !body.scanned_hashes)
            throw new Error("Arachnid Shield answered without scanned_hashes");
        return body.scanned_hashes;
    }
}
//# sourceMappingURL=arachnid.js.map