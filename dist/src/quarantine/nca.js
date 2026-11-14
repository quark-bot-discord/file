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
/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export async function submitReferral(config, payload, files) {
    const form = new FormData();
    form.append("submission", new Blob([JSON.stringify(payload)], { type: "application/json" }));
    for (const f of files)
        form.append("uploadedFiles", new Blob([new Uint8Array(f.bytes)], { type: f.type }), f.name);
    const response = await (config.fetchImpl ?? fetch)(`${config.baseUrl}/api/referral/`, {
        method: "POST",
        headers: { "X-API-KEY": config.apiKey, orgId: config.orgId },
        body: form,
        signal: AbortSignal.timeout(120000),
    });
    const body = await response.text().catch(() => "");
    if (!response.ok)
        throw new NcaError(response.status, body, response.status === 400);
    let parsed = {};
    try {
        parsed = JSON.parse(body);
    }
    catch {
        // Handled below.
    }
    if (!parsed.referralFriendlyID || parsed.success === false)
        throw new NcaError(response.status, body || "no referral id in the answer", false);
    return {
        referralID: String(parsed.referralID ?? ""),
        referralFriendlyID: parsed.referralFriendlyID,
        reportID: parsed.reportID,
    };
}
//# sourceMappingURL=nca.js.map