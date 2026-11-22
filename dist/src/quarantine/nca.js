export const DEFAULT_NCA_API_URL = "https://www.uk-child-sexual-abuse-industry-reporting.gov.uk/submission";
/** The API's settings, or undefined while any is missing. */
export function ncaConfigFromEnv(env = process.env) {
    const apiKey = env.NCA_API_KEY;
    const orgId = env.NCA_ORG_ID;
    const firstName = env.NCA_REPORTER_FIRST_NAME;
    const lastName = env.NCA_REPORTER_LAST_NAME;
    const email = env.NCA_REPORTER_EMAIL;
    if (!apiKey || !orgId || !firstName || !lastName || !email)
        return undefined;
    return {
        apiKey,
        orgId,
        baseUrl: (env.NCA_API_URL || DEFAULT_NCA_API_URL).replace(/\/+$/, ""),
        espName: env.NCA_ESP_NAME || "Quark Bot Limited",
        reporter: {
            firstName,
            lastName,
            email,
            phone: env.NCA_REPORTER_PHONE || "",
            phoneCountryCode: env.NCA_REPORTER_PHONE_CC || "+44",
        },
    };
}
const ESCALATION = {
    "1": "Priority 1 - there is a current or immediate risk to an individual",
    "2": "Priority 2 - there is a possible risk to an individual in the near future or is time-sensitive",
    "3": "Priority 3 - other",
};
export function priorityIdOf(level) {
    return level === "immediate_risk" ? "1" : level === "serious_harm" ? "2" : "3";
}
export function methodOf(item) {
    const route = item.intake?.route;
    if (!route)
        return "An automated detection tool";
    if (route === "legal_report_form" || route === "support_server" || route === "email")
        return "A user of the platform";
    return "A third party reporter";
}
const NOT_HELD = "Data not held";
/** SI 2026/268, Schedule 1, item 5. */
export const DECLARATION = "Declaration (SI 2026/268, Schedule 1, item 5): Quark Bot Limited has provided all the information required by Schedule 1 that is available to it. Items it does not hold are listed above as not available.";
const text = (v) => (typeof v === "string" ? v : "");
/**
 * A date-time as in every example in the NCA's schema: `yyyy-MM-ddTHH:mm:ss`,
 * no milliseconds or zone (its parser rejects `.000Z` despite the docs).
 * Always UTC; the report says so in its additional information.
 */
const iso = (v) => {
    const t = typeof v === "string" ? Date.parse(v) : NaN;
    return Number.isNaN(t) ? "" : new Date(t).toISOString().slice(0, 19);
};
/** A phone number as the schema's "digits", with its calling code apart if given. */
export function phoneOf(raw, defaultCode = "") {
    const trimmed = raw.trim();
    let digits = trimmed.replace(/\D/g, "");
    const code = defaultCode.replace(/\D/g, "");
    if (trimmed.startsWith("+")) {
        // "+44 7700 900123": the code is in the number; split it off if it is ours.
        if (code && digits.startsWith(code))
            digits = digits.slice(code.length);
        else
            return { countryCallingCode: "", value: digits };
    }
    else if (code && digits.startsWith("0")) {
        // "07700 900123" with +44: the trunk 0 is not dialled after the code.
        digits = digits.slice(1);
    }
    return { countryCallingCode: defaultCode, value: digits };
}
function addressesOf(records) {
    const out = [];
    for (const r of records ?? [])
        for (const a of [r.address, ...(r.payment_methods ?? []).map((m) => m.address)]) {
            if (!a)
                continue;
            out.push({
                street1: text(a.line1),
                street2: text(a.line2),
                city: text(a.city),
                postalCode: text(a.postal_code),
                nonUsaState: text(a.state),
                country: text(a.country),
                type: "HOME",
            });
        }
    return out;
}
function valuesOf(records, key) {
    const out = new Set();
    for (const r of records ?? []) {
        if (r[key])
            out.add(String(r[key]));
        for (const m of r.payment_methods ?? [])
            if (m[key])
                out.add(String(m[key]));
    }
    return [...out];
}
/**
 * The SubmissionPayload for one item. `previousReferences` are the NCA
 * references of earlier reports this one relates to.
 */
export function ncaPayload(item, fields, config) {
    const priorityId = priorityIdOf(item.priority?.level);
    const user = fields["3_user"];
    const where = fields["6_when_and_where"];
    const how = fields["5_how_detected"];
    const content = fields["4_content"];
    const billing = (user.billing ?? []);
    const previous = fields["8_previous_reports"].reports.map((r) => r.reference);
    const isVideo = /^video\//.test(item.content.type ?? "");
    const emails = valuesOf(billing, "email");
    const phones = valuesOf(billing, "phone");
    const names = valuesOf(billing, "name");
    const info = (lines) => lines.filter((l) => !!l).map((value) => ({ value: value.slice(0, 4000) }));
    // The NCA's example never leaves a list empty: where nothing is held it has
    // one entry saying so ("Data not held"), or one blank entry. Do the same,
    // in case their mapper reads the first entry of a list without checking.
    const noEmail = [{ value: NOT_HELD, verified: false, verificationDate: "" }];
    const noPhone = [{ value: NOT_HELD, countryCallingCode: "", verified: false, verificationDate: "" }];
    const noCapture = [{ captureType: "IP address", value: "", eventName: "LOGIN", dateTime: "" }];
    const notHeldPerson = (senderStatus) => ({
        firstName: "",
        middleName: "",
        lastName: "",
        senderStatus,
        screenName: NOT_HELD,
        espUserId: "",
        ipAddress: NOT_HELD,
        dateOfBirth: "",
        billingDateOfBirth: "",
        billingName: NOT_HELD,
        dateAccountClosed: "",
        accountClosed: false,
        userNotifiedOfAccountcloser: false,
        profileUrl: [NOT_HELD],
        additionalEmails: [{ email: [{ value: "" }] }],
        emails: { email: noEmail },
        phones: { phone: noPhone },
        addresses: { address: [] },
        billingAddress: { address: [] },
        recoveryEmail: { email: [{ value: NOT_HELD }] },
        recoveryPhoneNumber: { phone: [{ value: "", countryCallingCode: "" }] },
        sourceInformation: { sourceCapture: noCapture },
        additionalInformation: [
            {
                value: senderStatus === "recipient"
                    ? "No intended recipient: the content was posted to a server channel, not sent to a person."
                    : "The account that posted the content is not known.",
            },
        ],
        bankAccountDetails: "",
        onlinePaymentPlatformDetails: "",
        creditCardDetails: "",
        otherAccountsLinkedToUser: "",
        recoveryAccount: "",
        fraudulentAccountReason: "",
        additionalUsernames: "",
        passportNumber: "",
        niNumber: "",
        drivingLicense: "",
        bio: "",
        profilePictureAttached: false,
        biometricDataAttached: false,
        voiceRecordingsAttached: false,
        idUploadAttached: false,
        userProvidedIdentificationRadio: false,
    });
    const reportedPerson = user.discord_user_id
        ? [
            {
                firstName: "",
                middleName: "",
                lastName: "",
                senderStatus: "sender",
                screenName: user.username || user.discord_user_id,
                espUserId: user.discord_user_id,
                ipAddress: NOT_HELD,
                dateOfBirth: "",
                billingDateOfBirth: "",
                billingName: names[0] ?? NOT_HELD,
                dateAccountClosed: "",
                accountClosed: false,
                userNotifiedOfAccountcloser: false,
                profileUrl: user.profile_url ? [user.profile_url] : [NOT_HELD],
                additionalEmails: [{ email: [{ value: "" }] }],
                emails: { email: emails.length ? emails.map((value) => ({ value, verified: false, verificationDate: "" })) : noEmail },
                phones: { phone: phones.length ? phones.map((raw) => ({ ...phoneOf(raw), verified: false, verificationDate: "" })) : noPhone },
                addresses: { address: [] },
                billingAddress: { address: addressesOf(billing) },
                recoveryEmail: { email: [{ value: NOT_HELD }] },
                recoveryPhoneNumber: { phone: [{ value: "", countryCallingCode: "" }] },
                sourceInformation: { sourceCapture: noCapture },
                additionalInformation: info([
                    user.display_name && `Display name: ${user.display_name}`,
                    user.account_created_at && `Discord account created: ${user.account_created_at}`,
                    "Discord does not give bots email addresses, phone numbers or IP addresses. Contact details above, if any, are from Quark's own billing records.",
                ]),
                bankAccountDetails: "",
                onlinePaymentPlatformDetails: billing.map((b) => b.source).join(", "),
                creditCardDetails: "",
                otherAccountsLinkedToUser: "",
                recoveryAccount: "",
                fraudulentAccountReason: "",
                additionalUsernames: "",
                passportNumber: "",
                niNumber: "",
                drivingLicense: "",
                bio: "",
                profilePictureAttached: false,
                biometricDataAttached: false,
                voiceRecordingsAttached: false,
                idUploadAttached: false,
                userProvidedIdentificationRadio: false,
            },
        ]
        : [notHeldPerson("sender")];
    const hashes = [
        content.sha256 && `SHA-256: ${content.sha256}`,
        how.pdq_hash_hex && `PDQ: ${how.pdq_hash_hex}`,
    ].filter((h) => !!h);
    const uploadedFile = item.content.stored
        ? [
            {
                originalFilename: content.file_name || `quarantine-${item.id}`,
                uploadedDateTime: iso(where.posted_or_uploaded_at) || iso(item.detected_at),
                ipAddress: NOT_HELD,
                potentialMeme: false,
                links: { link: [{ href: where.url || NOT_HELD, rel: "URL of content" }] },
                originalFileHashes: { originalFileHash: hashes.map((value) => ({ value })) },
                sourceInformation: { sourceCapture: noCapture },
                additionalInformation: info([
                    user.ip_address && `IP address the file was uploaded from: ${user.ip_address} at ${user.ip_address_time}`,
                    content.held,
                ]),
            },
        ]
        : [];
    return {
        about: `Quark ${item.intake ? `report via ${item.intake.route}` : `${how.classification} match`} (quarantine ${item.id})`,
        priorityId,
        potentialMemeReport: false,
        reportedInformation: {
            incidentSummary: {
                espEscalation: ESCALATION[priorityId],
                humanModerator: false,
                incidentDateTime: iso(where.posted_or_uploaded_at) || iso(item.detected_at),
                incidentType: item.content.stored ? (isVideo ? "Indecent video of children" : "Indecent imagery of children") : "Other",
                materialAltered: false,
                methodOfDetection: methodOf(item),
                additionalInfo: item.intake
                    ? `Reported to Quark (${item.intake.route}). ${item.intake.summary ?? ""} Not viewed by Quark.`.slice(0, 4000)
                    : `${how.method} Classification: ${how.classification}. Not viewed by Quark.`,
                relatedPreviousReferrals: previous.join(","),
                additionalDocuments: [],
            },
            additionalInformation: info([
                `Where: ${where.where}`,
                where.url && `Link: ${where.url}`,
                where.discord_server_id && `Discord server ID: ${where.discord_server_id}${where.discord_server_name ? ` (${where.discord_server_name})` : ""}`,
                where.discord_channel_id && `Discord channel ID: ${where.discord_channel_id}`,
                where.discord_message_id && `Discord message ID: ${where.discord_message_id}`,
                where.discord_attachment_id && `Discord attachment ID: ${where.discord_attachment_id}`,
                `Detected by Quark: ${item.detected_at}`,
                "All dates and times in this report are UTC.",
                ...fields.not_available.map((n) => `Not available: ${n}`),
                "Everything else Quark holds, including the user's relevant data from the two weeks before, is attached as quark-report.json.",
                DECLARATION,
            ]).concat(relevantDataLines(fields)),
            incidentDetails: {
                chatIncident: where.discord_server_id
                    ? [{ screenName: where.discord_server_name || `Discord server ${where.discord_server_id}`, chatRoomName: where.discord_channel_id ? `Discord channel ${where.discord_channel_id}` : "" }]
                    : [],
            },
            intendedRecipients: { intendedRecipient: [notHeldPerson("recipient")] },
            lawEnforcementInformation: {
                caseNumber: item.intake?.route === "police" ? text(item.intake.reference) : "",
                reportedToLawEnforcement: item.intake?.route === "police",
                investigator: {
                    firstName: "",
                    lastName: "",
                    emails: { email: [{ value: "" }] },
                    phones: { phone: [{ countryCallingCode: "", value: "" }] },
                },
            },
            reportedPeople: { reportedPerson },
            reportingEsp: {
                espName: config.espName,
                organisationId: config.orgId,
                platform: "Quark (Discord bot and quark.bot)",
                firstName: config.reporter.firstName,
                lastName: config.reporter.lastName,
                phones: {
                    phone: config.reporter.phone
                        ? [phoneOf(config.reporter.phone, config.reporter.phoneCountryCode)]
                        : [{ countryCallingCode: "", value: NOT_HELD }],
                },
                emails: { email: [{ value: config.reporter.email }] },
            },
            uploadedFiles: { uploadedFile },
        },
    };
}
const RETRY_STATUSES = new Set([408, 429, 503]);
export function kindOfStatus(status) {
    if (RETRY_STATUSES.has(status))
        return "retry";
    if (status >= 500 || (status >= 200 && status < 300))
        return "uncertain";
    return "refused";
}
export class NcaError extends Error {
    constructor(status, body, kind = kindOfStatus(status)) {
        super(`NCA API ${status}: ${body.slice(0, 500)}`);
        this.status = status;
        this.body = body;
        this.name = "NcaError";
        this.kind = kind;
    }
    /** Not tried again automatically. */
    get permanent() {
        return this.kind !== "retry";
    }
}
/** A failure before anything was sent (e.g. completing the certificate chain). */
export class NcaNotSentError extends Error {
    constructor(message, cause) {
        super(message);
        this.cause = cause;
        this.name = "NcaNotSentError";
    }
}
/**
 * Something on Quark's side stopped the report before anything was sent
 * (e.g. the stored file is missing or does not match its checksum). Not
 * retried: a person has to look at the item.
 */
export class NcaLocalError extends Error {
    constructor(message) {
        super(message);
        this.name = "NcaLocalError";
    }
}
/** Network errors that mean the request never reached the NCA. */
const NOT_SENT_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "UND_ERR_CONNECT_TIMEOUT"]);
/** How to treat any error from `submitReferral`. */
export function ncaFailureKind(error) {
    if (error?.name === "NcaError")
        return error.kind;
    if (error?.name === "NcaNotSentError")
        return "retry";
    if (error?.name === "NcaLocalError")
        return "refused";
    const code = error?.cause?.code ?? error?.code ?? "";
    if (NOT_SENT_CODES.has(code) || /^(CERT_|UNABLE_TO_|ERR_TLS_|DEPTH_ZERO|SELF_SIGNED)/.test(code))
        return "retry";
    return "uncertain";
}
/**
 * The NCA's server sends its certificate without the intermediate that links
 * it to a trusted root (seen November 2026: issued by Amazon RSA 2048 M04).
 * Browsers fetch the missing intermediate themselves; Node does not, and
 * fails with UNABLE_TO_VERIFY_LEAF_SIGNATURE. So, on that error only, do what
 * a browser does: read the certificate's "CA Issuers" address, fetch the
 * intermediate from there, and send again with it added. Verification is
 * unchanged: the chain must still end at one of Node's trusted roots, and
 * an intermediate is only accepted if it issued that certificate.
 */
const intermediates = new Map();
const isIncompleteChain = (error) => {
    const code = error?.cause?.code ?? error?.code;
    return code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
};
/** The server's own certificate, read only to find where its issuer is published. */
async function leafOf(host, port) {
    const tls = await import("tls");
    const { X509Certificate } = await import("crypto");
    const raw = await new Promise((resolve, reject) => {
        const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
            const cert = socket.getPeerCertificate();
            socket.end();
            if (cert?.raw)
                resolve(cert.raw);
            else
                reject(new Error(`${host} sent no certificate`));
        });
        socket.setTimeout(15000, () => socket.destroy(new Error(`${host}: timed out reading its certificate`)));
        socket.on("error", reject);
    });
    return new X509Certificate(raw);
}
/** The intermediate that issued `host`'s certificate, as PEM, from its CA Issuers address. */
export async function intermediateFor(host, port = 443, fetchImpl = fetch) {
    const cached = intermediates.get(`${host}:${port}`);
    if (cached)
        return cached;
    const { X509Certificate } = await import("crypto");
    const leaf = await leafOf(host, port);
    const url = /CA Issuers - URI:(\S+)/.exec(leaf.infoAccess ?? "")?.[1];
    if (!url)
        throw new Error(`${host}'s certificate does not say where its issuer is published`);
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(20000) });
    if (!response.ok)
        throw new Error(`Fetching ${url}: ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    const issuer = new X509Certificate(bytes.toString("latin1").includes("-----BEGIN") ? bytes.toString("latin1") : bytes);
    if (!issuer.ca || !leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey))
        throw new Error(`${url} is not the certificate that issued ${host}'s`);
    intermediates.set(`${host}:${port}`, issuer.toString());
    return issuer.toString();
}
/** POST with Node's https, trusting its usual roots plus `extraCa` as an intermediate. */
async function postWithCa(url, headers, form, extraCa, roots) {
    const https = await import("https");
    const encoded = new Request(url, { method: "POST", body: form });
    const body = Buffer.from(await encoded.arrayBuffer());
    const type = encoded.headers.get("content-type") ?? "multipart/form-data";
    return new Promise((resolve, reject) => {
        const request = https.request(url, {
            method: "POST",
            headers: { ...headers, "Content-Type": type, "Content-Length": String(body.length) },
            ca: [...roots, extraCa],
            timeout: 120000,
        }, (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
                const status = res.statusCode ?? 0;
                resolve({ status, ok: status >= 200 && status < 300, body: Buffer.concat(chunks).toString("utf8") });
            });
            res.on("error", reject);
        });
        request.on("timeout", () => request.destroy(new Error("NCA API: timed out")));
        request.on("error", reject);
        request.end(body);
    });
}
/** One POST to the referral endpoint; the raw answer, whatever its status. */
export async function postReferral(config, payload, files, encoding = "text") {
    const form = () => {
        const f = new FormData();
        // The NCA wants the JSON as a text field, not a file part (NCA support, 16/11/2026).
        if (encoding === "text")
            f.append("submission", JSON.stringify(payload));
        else
            f.append("submission", new Blob([JSON.stringify(payload)], { type: "application/json" }));
        for (const file of files)
            f.append("uploadedFiles", new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
        return f;
    };
    const url = `${config.baseUrl}/api/referral/`;
    const headers = { "X-API-KEY": config.apiKey, orgId: config.orgId };
    try {
        const response = await (config.fetchImpl ?? fetch)(url, {
            method: "POST",
            headers,
            body: form(),
            signal: AbortSignal.timeout(120000),
        });
        return { status: response.status, ok: response.ok, body: await response.text().catch(() => "") };
    }
    catch (error) {
        if (!isIncompleteChain(error))
            throw error;
        const target = new URL(url);
        let intermediate;
        try {
            intermediate = await intermediateFor(target.hostname, Number(target.port) || 443);
        }
        catch (chainError) {
            throw new NcaNotSentError(`Completing the NCA's certificate chain: ${chainError?.message}`, chainError);
        }
        const roots = config.rootCertificates ?? (await import("tls")).rootCertificates;
        try {
            return await postWithCa(url, headers, form(), intermediate, roots);
        }
        catch (retryError) {
            // The NCA may have moved to another intermediate: fetch it afresh next time.
            intermediates.delete(`${target.hostname}:${Number(target.port) || 443}`);
            throw retryError;
        }
    }
}
/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export async function submitReferral(config, payload, files, encoding = "text") {
    const { status, ok, body } = await postReferral(config, payload, files, encoding);
    if (!ok)
        throw new NcaError(status, body);
    let parsed = {};
    try {
        parsed = JSON.parse(body);
    }
    catch {
        // Handled below.
    }
    if (!parsed.referralFriendlyID || parsed.success === false)
        throw new NcaError(status, body || "no referral id in the answer", "uncertain");
    return {
        referralID: String(parsed.referralID ?? ""),
        referralFriendlyID: parsed.referralFriendlyID,
        reportID: parsed.reportID,
    };
}
/** What a file actually is, from its first bytes: [MIME type, extension]. */
export function sniffMedia(bytes) {
    const h = bytes.subarray(0, 12).toString("hex");
    if (h.startsWith("47494638"))
        return ["image/gif", "gif"];
    if (h.startsWith("89504e470d0a1a0a"))
        return ["image/png", "png"];
    if (h.startsWith("ffd8ff"))
        return ["image/jpeg", "jpg"];
    if (h.startsWith("52494646") && h.slice(16, 24) === "57454250")
        return ["image/webp", "webp"];
    if (h.startsWith("424d"))
        return ["image/bmp", "bmp"];
    if (h.startsWith("49492a00") || h.startsWith("4d4d002a"))
        return ["image/tiff", "tif"];
    if (h.slice(8, 16) === "66747970") {
        const brand = bytes.subarray(8, 12).toString("latin1");
        if (/^(avif|avis)$/.test(brand))
            return ["image/avif", "avif"];
        if (/^(heic|heix|mif1|msf1)$/.test(brand))
            return ["image/heic", "heic"];
        if (brand === "qt  ")
            return ["video/quicktime", "mov"];
        return ["video/mp4", "mp4"];
    }
    if (h.startsWith("1a45dfa3"))
        return ["video/webm", "webm"];
    return null;
}
/**
 * The name and type to send a file under: the type from the file itself, not
 * from what Discord said, and a plain-ASCII name ending in the matching
 * extension (Discord names can be anything).
 */
export function mediaNameAndType(bytes, originalName, id) {
    const sniffed = sniffMedia(bytes);
    const raw = (originalName ?? "").replace(/\.[A-Za-z0-9]{1,5}$/, "");
    const base = raw.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._]+|[._]+$/g, "").slice(0, 80) || `quarantine-${id}`;
    if (!sniffed) {
        const ext = /\.([A-Za-z0-9]{1,5})$/.exec(originalName ?? "")?.[1]?.toLowerCase();
        return { name: ext ? `${base}.${ext}` : base, type: "application/octet-stream" };
    }
    return { name: `${base}.${sniffed[1]}`, type: sniffed[0] };
}
/**
 * The two weeks of relevant data, also in the report's own text, so it reaches
 * the NCA even if quark-report.json does not (their system takes media
 * files; whether it keeps others is not documented). At most
 * `RELEVANT_TEXT_ENTRIES` entries of 4,000 characters; the rest is in the
 * attached file, and the text says so.
 */
export const RELEVANT_TEXT_ENTRIES = 10;
export function relevantDataLines(fields) {
    const data = fields["7_relevant_data_two_weeks"];
    const hasAny = data && (data.at_match != null || Object.keys(data.added_since ?? {}).length > 0);
    if (!hasAny)
        return [];
    const text = JSON.stringify(data);
    const size = 3900;
    const total = Math.ceil(text.length / size);
    const shown = Math.min(total, RELEVANT_TEXT_ENTRIES);
    const out = [];
    for (let i = 0; i < shown; i++)
        out.push({ value: `Relevant data, two weeks before (JSON, part ${i + 1} of ${total}): ${text.slice(i * size, (i + 1) * size)}` });
    if (total > shown)
        out.push({ value: `Relevant data continues in quark-report.json (parts ${shown + 1} to ${total} not repeated here).` });
    return out;
}
/**
 * Whether a file ends the way its format requires: true or false for GIF,
 * PNG, JPEG and WebP; null when the format is not one of those. A file cut
 * short in transit fails this.
 */
export function endsProperly(bytes) {
    const kind = sniffMedia(bytes)?.[1];
    if (kind === "gif")
        return bytes.at(-1) === 0x3b;
    if (kind === "png")
        return bytes.length >= 12 && bytes.subarray(-8, -4).toString("latin1") === "IEND";
    if (kind === "jpg") {
        // Some encoders add padding after the end marker.
        const tail = bytes.subarray(Math.max(0, bytes.length - 64));
        for (let i = tail.length - 2; i >= 0; i--)
            if (tail[i] === 0xff && tail[i + 1] === 0xd9)
                return true;
        return false;
    }
    if (kind === "webp")
        return bytes.length >= 12 && bytes.readUInt32LE(4) + 8 <= bytes.length;
    return null;
}
//# sourceMappingURL=nca.js.map