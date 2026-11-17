/**
 * Reports to the NCA through the CSEA Industry Reporting Portal's submission
 * API (`POST /submission/api/referral/`, multipart: a `submission` JSON field
 * and the files as `uploadedFiles` parts), server to server: the file goes
 * from the quarantine to the NCA and is never downloaded by anyone.
 *
 *   NCA_API_KEY            the organisation's API key (X-API-KEY)
 *   NCA_ORG_ID             the organisation's UUID (orgId header, reportingEsp)
 *   NCA_API_URL            default https://www.uk-child-sexual-abuse-industry-reporting.gov.uk/submission
 *   NCA_REPORTER_FIRST_NAME, NCA_REPORTER_LAST_NAME, NCA_REPORTER_EMAIL,
 *   NCA_REPORTER_PHONE, NCA_REPORTER_PHONE_CC (default +44)
 *                          the person the NCA contacts (Schedule 1, item 1)
 *   NCA_ESP_NAME           default "Quark Bot Limited"
 *
 * `ncaPayload` maps the report's fields (`reportFieldsOf`) onto the API's
 * SubmissionPayload; everything else Quark holds goes with it as a JSON
 * document, so nothing in Schedule 1 is left out for want of a field.
 */
import type {
  BillingRecord,
  Priority,
  QuarantineItem,
  reportFieldsOf,
} from "./index.js";

export const DEFAULT_NCA_API_URL =
  "https://www.uk-child-sexual-abuse-industry-reporting.gov.uk/submission";

export interface NcaConfig {
  apiKey: string;
  orgId: string;
  baseUrl: string;
  espName: string;
  reporter: {
    firstName: string;
    lastName: string;
    email: string;
    phone: string;
    phoneCountryCode: string;
  };
  fetchImpl?: typeof fetch;
  /** Tests only: the roots trusted when the server's chain has to be completed. */
  rootCertificates?: readonly string[];
}

/** The API's settings, or undefined while any is missing. */
export function ncaConfigFromEnv(env: NodeJS.ProcessEnv = process.env): NcaConfig | undefined {
  const apiKey = env.NCA_API_KEY;
  const orgId = env.NCA_ORG_ID;
  const firstName = env.NCA_REPORTER_FIRST_NAME;
  const lastName = env.NCA_REPORTER_LAST_NAME;
  const email = env.NCA_REPORTER_EMAIL;
  if (!apiKey || !orgId || !firstName || !lastName || !email) return undefined;
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

const ESCALATION: Record<"1" | "2" | "3", string> = {
  "1": "Priority 1 - there is a current or immediate risk to an individual",
  "2": "Priority 2 - there is a possible risk to an individual in the near future or is time-sensitive",
  "3": "Priority 3 - other",
};

export function priorityIdOf(level: Priority | null | undefined): "1" | "2" | "3" {
  return level === "immediate_risk" ? "1" : level === "serious_harm" ? "2" : "3";
}

/** How the content came to light, in the API's words. */
export type DetectionMethod =
  | "A user of the platform"
  | "A third party reporter"
  | "An automated detection tool"
  | "An employee moderating the platform";

export function methodOf(item: QuarantineItem): DetectionMethod {
  const route = item.intake?.route;
  if (!route) return "An automated detection tool";
  if (route === "legal_report_form" || route === "support_server" || route === "email")
    return "A user of the platform";
  return "A third party reporter";
}

const NOT_HELD = "Data not held";
const text = (v: unknown) => (typeof v === "string" ? v : "");
/**
 * A date-time as in every example in the NCA's schema: `yyyy-MM-ddTHH:mm:ss`,
 * no milliseconds or zone (its parser rejects `.000Z` despite the docs).
 * Always UTC; the report says so in its additional information.
 */
const iso = (v: unknown) => {
  const t = typeof v === "string" ? Date.parse(v) : NaN;
  return Number.isNaN(t) ? "" : new Date(t).toISOString().slice(0, 19);
};

/** A phone number as the schema's "digits", with its calling code apart if given. */
export function phoneOf(raw: string, defaultCode = ""): { countryCallingCode: string; value: string } {
  const trimmed = raw.trim();
  let digits = trimmed.replace(/\D/g, "");
  const code = defaultCode.replace(/\D/g, "");
  if (trimmed.startsWith("+")) {
    // "+44 7700 900123": the code is in the number; split it off if it is ours.
    if (code && digits.startsWith(code)) digits = digits.slice(code.length);
    else return { countryCallingCode: "", value: digits };
  } else if (code && digits.startsWith("0")) {
    // "07700 900123" with +44: the trunk 0 is not dialled after the code.
    digits = digits.slice(1);
  }
  return { countryCallingCode: defaultCode, value: digits };
}

function addressesOf(records: BillingRecord[] | null | undefined) {
  const out: Record<string, string>[] = [];
  for (const r of records ?? [])
    for (const a of [r.address, ...(r.payment_methods ?? []).map((m) => m.address)]) {
      if (!a) continue;
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

function valuesOf(records: BillingRecord[] | null | undefined, key: "email" | "phone" | "name") {
  const out = new Set<string>();
  for (const r of records ?? []) {
    if (r[key]) out.add(String(r[key]));
    for (const m of r.payment_methods ?? []) if (m[key]) out.add(String(m[key]));
  }
  return [...out];
}

type Fields = ReturnType<typeof reportFieldsOf>;

/**
 * The SubmissionPayload for one item. `previousReferences` are the NCA
 * references of earlier reports this one relates to.
 */
export function ncaPayload(item: QuarantineItem, fields: Fields, config: NcaConfig) {
  const priorityId = priorityIdOf(item.priority?.level);
  const user = fields["3_user"];
  const where = fields["6_when_and_where"];
  const how = fields["5_how_detected"];
  const content = fields["4_content"];
  const billing = (user.billing ?? []) as BillingRecord[];
  const previous = fields["8_previous_reports"].reports.map((r) => r.reference);
  const isVideo = /^video\//.test(item.content.type ?? "");
  const emails = valuesOf(billing, "email");
  const phones = valuesOf(billing, "phone");
  const names = valuesOf(billing, "name");

  const info = (lines: (string | null | undefined | false)[]) =>
    lines.filter((l): l is string => !!l).map((value) => ({ value: value.slice(0, 4000) }));

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
          phones: { phone: phones.map((raw) => ({ ...phoneOf(raw), verified: false, verificationDate: "" })) },
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
  ].filter((h): h is string => !!h);

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
        "All dates and times in this report are UTC.",
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
            ? [phoneOf(config.reporter.phone, config.reporter.phoneCountryCode)]
            : [],
        },
        emails: { email: [{ value: config.reporter.email }] },
      },
      uploadedFiles: { uploadedFile },
    },
  };
}

export interface NcaResult {
  referralID: string;
  referralFriendlyID: string;
  reportID?: number;
}

/**
 * What a failed attempt means for trying again:
 * - `retry`: the NCA certainly did not process it (no connection was made,
 *   or it answered 408, 429 or 503). Tried again automatically.
 * - `refused`: the NCA rejected the report (400, 404, 413, 415, 422 and other
 *   client errors). Trying again unchanged will not help.
 * - `uncertain`: it may have been received: a 5xx except 503, a dropped
 *   connection, a timeout, or a 2xx without a referral number. Not tried
 *   again, so it is not reported twice: check the portal first.
 *
 * 401 and 403 count as `refused`. The NCA's API checks the key before the
 * report, and until its next release answers 401 when the real problem is the
 * report's data mapping (NCA support, 16/11/2026); either way nothing was
 * received, and retrying unchanged will not help.
 */
export type NcaFailureKind = "retry" | "refused" | "uncertain";

const RETRY_STATUSES = new Set([408, 429, 503]);

export function kindOfStatus(status: number): NcaFailureKind {
  if (RETRY_STATUSES.has(status)) return "retry";
  if (status >= 500 || (status >= 200 && status < 300)) return "uncertain";
  return "refused";
}

export class NcaError extends Error {
  public readonly kind: NcaFailureKind;
  constructor(
    public readonly status: number,
    public readonly body: string,
    kind: NcaFailureKind = kindOfStatus(status),
  ) {
    super(`NCA API ${status}: ${body.slice(0, 500)}`);
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
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "NcaNotSentError";
  }
}

/** Network errors that mean the request never reached the NCA. */
const NOT_SENT_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "UND_ERR_CONNECT_TIMEOUT"]);

/** How to treat any error from `submitReferral`. */
export function ncaFailureKind(error: unknown): NcaFailureKind {
  if ((error as Error)?.name === "NcaError") return (error as NcaError).kind;
  if ((error as Error)?.name === "NcaNotSentError") return "retry";
  const code = (error as { cause?: { code?: string }; code?: string })?.cause?.code ?? (error as { code?: string })?.code ?? "";
  if (NOT_SENT_CODES.has(code) || /^(CERT_|UNABLE_TO_|ERR_TLS_|DEPTH_ZERO|SELF_SIGNED)/.test(code)) return "retry";
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
const intermediates = new Map<string, string>();

const isIncompleteChain = (error: unknown) => {
  const code = (error as { cause?: { code?: string }; code?: string })?.cause?.code ?? (error as { code?: string })?.code;
  return code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
};

/** The server's own certificate, read only to find where its issuer is published. */
async function leafOf(host: string, port: number): Promise<import("crypto").X509Certificate> {
  const tls = await import("tls");
  const { X509Certificate } = await import("crypto");
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (cert?.raw) resolve(cert.raw);
      else reject(new Error(`${host} sent no certificate`));
    });
    socket.setTimeout(15_000, () => socket.destroy(new Error(`${host}: timed out reading its certificate`)));
    socket.on("error", reject);
  });
  return new X509Certificate(raw);
}

/** The intermediate that issued `host`'s certificate, as PEM, from its CA Issuers address. */
export async function intermediateFor(host: string, port = 443, fetchImpl: typeof fetch = fetch): Promise<string> {
  const cached = intermediates.get(`${host}:${port}`);
  if (cached) return cached;
  const { X509Certificate } = await import("crypto");
  const leaf = await leafOf(host, port);
  const url = /CA Issuers - URI:(\S+)/.exec(leaf.infoAccess ?? "")?.[1];
  if (!url) throw new Error(`${host}'s certificate does not say where its issuer is published`);
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`Fetching ${url}: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const issuer = new X509Certificate(bytes.toString("latin1").includes("-----BEGIN") ? bytes.toString("latin1") : bytes);
  if (!issuer.ca || !leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey))
    throw new Error(`${url} is not the certificate that issued ${host}'s`);
  intermediates.set(`${host}:${port}`, issuer.toString());
  return issuer.toString();
}

/** POST with Node's https, trusting its usual roots plus `extraCa` as an intermediate. */
async function postWithCa(
  url: string,
  headers: Record<string, string>,
  form: FormData,
  extraCa: string,
  roots: readonly string[],
): Promise<{ status: number; ok: boolean; body: string }> {
  const https = await import("https");
  const encoded = new Request(url, { method: "POST", body: form });
  const body = Buffer.from(await encoded.arrayBuffer());
  const type = encoded.headers.get("content-type") ?? "multipart/form-data";
  return new Promise((resolve, reject) => {
    const request = https.request(
      url,
      {
        method: "POST",
        headers: { ...headers, "Content-Type": type, "Content-Length": String(body.length) },
        ca: [...roots, extraCa],
        timeout: 120_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          resolve({ status, ok: status >= 200 && status < 300, body: Buffer.concat(chunks).toString("utf8") });
        });
        res.on("error", reject);
      },
    );
    request.on("timeout", () => request.destroy(new Error("NCA API: timed out")));
    request.on("error", reject);
    request.end(body);
  });
}

/** How the `submission` field is encoded: plain text (as NCA support asked), or a JSON part. */
export type SubmissionEncoding = "text" | "json";

/** One POST to the referral endpoint; the raw answer, whatever its status. */
export async function postReferral(
  config: NcaConfig,
  payload: unknown,
  files: { name: string; type: string; bytes: Buffer }[],
  encoding: SubmissionEncoding = "text",
): Promise<{ status: number; ok: boolean; body: string }> {
  const form = () => {
    const f = new FormData();
    // The NCA wants the JSON as a text field, not a file part (NCA support, 16/11/2026).
    if (encoding === "text") f.append("submission", JSON.stringify(payload));
    else f.append("submission", new Blob([JSON.stringify(payload)], { type: "application/json" }));
    for (const file of files) f.append("uploadedFiles", new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
    return f;
  };
  const url = `${config.baseUrl}/api/referral/`;
  const headers = { "X-API-KEY": config.apiKey, orgId: config.orgId };
  try {
    const response = await (config.fetchImpl ?? fetch)(url, {
      method: "POST",
      headers,
      body: form(),
      signal: AbortSignal.timeout(120_000),
    });
    return { status: response.status, ok: response.ok, body: await response.text().catch(() => "") };
  } catch (error) {
    if (!isIncompleteChain(error)) throw error;
    const target = new URL(url);
    let intermediate: string;
    try {
      intermediate = await intermediateFor(target.hostname, Number(target.port) || 443);
    } catch (chainError) {
      throw new NcaNotSentError(`Completing the NCA's certificate chain: ${(chainError as Error)?.message}`, chainError);
    }
    const roots = config.rootCertificates ?? (await import("tls")).rootCertificates;
    try {
      return await postWithCa(url, headers, form(), intermediate, roots);
    } catch (retryError) {
      // The NCA may have moved to another intermediate: fetch it afresh next time.
      intermediates.delete(`${target.hostname}:${Number(target.port) || 443}`);
      throw retryError;
    }
  }
}

/** POSTs one referral. The file and the JSON document go as `uploadedFiles`. */
export async function submitReferral(
  config: NcaConfig,
  payload: unknown,
  files: { name: string; type: string; bytes: Buffer }[],
  encoding: SubmissionEncoding = "text",
): Promise<NcaResult> {
  const { status, ok, body } = await postReferral(config, payload, files, encoding);
  if (!ok) throw new NcaError(status, body);
  let parsed: Partial<NcaResult> & { success?: boolean } = {};
  try {
    parsed = JSON.parse(body);
  } catch {
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

/** One probe of `checkWithNca`. */
export interface NcaProbe {
  step: string;
  sent: string;
  status: number | null;
  body: string;
  meaning: string;
}

/** A priorityId outside the enumeration: the NCA must reject any report carrying it. */
const INVALID_PRIORITY = "0";

/**
 * Find out, without reporting anything, whether the NCA accepts the key and
 * can read a report. Every probe is invalid on purpose, so none can create a
 * referral, and none carries the reported file:
 *  1. `{}` (missing required fields): 400 means the key is good; 401, the key.
 *  2. The real report with priorityId "0" and no files, as text, then
 *  3. as a JSON part: a 400 listing errors means the NCA read it (the list is
 *     what to fix besides the priority); a 401 means it could not read it.
 *  4. As 2, with quark-report.json attached: does the extra file break it?
 * Until the NCA's next release a 401 also stands for "could not read the data".
 */
export async function probeNca(
  config: NcaConfig,
  payload: Record<string, unknown>,
  reportJson: { name: string; type: string; bytes: Buffer },
): Promise<NcaProbe[]> {
  const invalid = { ...payload, priorityId: INVALID_PRIORITY };
  const probes: [string, string, unknown, { name: string; type: string; bytes: Buffer }[], SubmissionEncoding][] = [
    ["key", "an empty report, {}", {}, [], "text"],
    ["report as text", 'the real report with priorityId "0", no files, submission as a text field', invalid, [], "text"],
    ["report as JSON part", 'the same, submission as an application/json part', invalid, [], "json"],
    ["with quark-report.json", 'the same as text, with quark-report.json attached (never the reported file)', invalid, [reportJson], "text"],
  ];
  const out: NcaProbe[] = [];
  for (const [step, sent, body, files, encoding] of probes) {
    try {
      // eslint-disable-next-line no-await-in-loop
      const answer = await postReferral(config, body, files, encoding);
      out.push({ step, sent, status: answer.status, body: answer.body.slice(0, 2000), meaning: meaningOf(step, answer.status) });
    } catch (error) {
      out.push({ step, sent, status: null, body: `${(error as Error)?.message ?? error}`.slice(0, 500), meaning: "Could not reach the NCA." });
    }
  }
  return out;
}

function meaningOf(step: string, status: number): string {
  if (status >= 200 && status < 300)
    return "The NCA ACCEPTED this test, which it should not have. Tell NCA support its referral number (in the answer) so they can discard it.";
  if (step === "key")
    return status === 401 ? "The NCA refused the API key (or could not read even an empty report)." : status === 400 ? "The API key is accepted." : `Unexpected answer ${status}.`;
  if (status === 400) return "The NCA could read the report. Everything listed in the answer, other than priorityId, needs fixing.";
  if (status === 401) return "The NCA could not read the report in this form (its API answers 401 for this).";
  return `Unexpected answer ${status}.`;
}
