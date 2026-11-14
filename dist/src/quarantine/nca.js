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
const text = (v) => (typeof v === "string" ? v : "");
const iso = (v) => {
    const t = typeof v === "string" ? Date.parse(v) : NaN;
    return Number.isNaN(t) ? "" : new Date(t).toISOString();
};
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
                profileUrl: user.profile_url ? [user.profile_url] : [],
                additionalEmails: [],
                emails: { email: emails.map((value) => ({ value, verified: false, verificationDate: "" })) },
                phones: { phone: phones.map((value) => ({ value, countryCallingCode: "", verified: false, verificationDate: "" })) },
                addresses: { address: [] },
                billingAddress: { address: addressesOf(billing) },
                recoveryEmail: { email: [{ value: NOT_HELD }] },
                recoveryPhoneNumber: { phone: [] },
                sourceInformation: { sourceCapture: [] },
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
        : [];
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
                links: { link: where.url ? [{ href: where.url, rel: "URL of content" }] : [] },
                originalFileHashes: { originalFileHash: hashes.map((value) => ({ value })) },
                sourceInformation: { sourceCapture: [] },
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
                ...fields.not_available.map((n) => `Not available: ${n}`),
                "Everything else Quark holds, including the user's relevant data from the two weeks before, is attached as quark-report.json.",
            ]),
            incidentDetails: {
                chatIncident: where.discord_server_id
                    ? [{ screenName: where.discord_server_name || `Discord server ${where.discord_server_id}`, chatRoomName: where.discord_channel_id ? `Discord channel ${where.discord_channel_id}` : "" }]
                    : [],
            },
            intendedRecipients: { intendedRecipient: [] },
            lawEnforcementInformation: {
                caseNumber: item.intake?.route === "police" ? text(item.intake.reference) : "",
                reportedToLawEnforcement: item.intake?.route === "police",
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
                        ? [{ countryCallingCode: config.reporter.phoneCountryCode, value: config.reporter.phone }]
                        : [],
                },
                emails: { email: [{ value: config.reporter.email }] },
            },
            uploadedFiles: { uploadedFile },
        },
    };
}
export class NcaError extends Error {
    constructor(status, body, 
    /** 400: the report itself is wrong; trying again will not help. */
    permanent) {
        super(`NCA API ${status}: ${body.slice(0, 500)}`);
        this.status = status;
        this.body = body;
        this.permanent = permanent;
        this.name = "NcaError";
    }
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
/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export async function submitReferral(config, payload, files) {
    const form = () => {
        const f = new FormData();
        f.append("submission", new Blob([JSON.stringify(payload)], { type: "application/json" }));
        for (const file of files)
            f.append("uploadedFiles", new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
        return f;
    };
    const url = `${config.baseUrl}/api/referral/`;
    const headers = { "X-API-KEY": config.apiKey, orgId: config.orgId };
    let status;
    let ok;
    let body;
    try {
        const response = await (config.fetchImpl ?? fetch)(url, {
            method: "POST",
            headers,
            body: form(),
            signal: AbortSignal.timeout(120000),
        });
        ({ status, ok } = response);
        body = await response.text().catch(() => "");
    }
    catch (error) {
        if (!isIncompleteChain(error))
            throw error;
        const target = new URL(url);
        const intermediate = await intermediateFor(target.hostname, Number(target.port) || 443);
        const roots = config.rootCertificates ?? (await import("tls")).rootCertificates;
        try {
            ({ status, ok, body } = await postWithCa(url, headers, form(), intermediate, roots));
        }
        catch (retryError) {
            // The NCA may have moved to another intermediate: fetch it afresh next time.
            intermediates.delete(`${target.hostname}:${Number(target.port) || 443}`);
            throw retryError;
        }
    }
    if (!ok)
        throw new NcaError(status, body, status === 400);
    let parsed = {};
    try {
        parsed = JSON.parse(body);
    }
    catch {
        // Handled below.
    }
    if (!parsed.referralFriendlyID || parsed.success === false)
        throw new NcaError(status, body || "no referral id in the answer", false);
    return {
        referralID: String(parsed.referralID ?? ""),
        referralFriendlyID: parsed.referralFriendlyID,
        reportID: parsed.reportID,
    };
}
//# sourceMappingURL=nca.js.map