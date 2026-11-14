/**
 * The restricted store for files that matched known child sexual abuse
 * material, and what a report to the NCA needs about each one.
 *
 * Under the CSEA reporting regulations (SI 2026/268) a provider that reports
 * keeps, for one year, the content, the report, the basis for it and the
 * user's relevant data from the two weeks before; the report reference is
 * kept for five years (reg 8), all of it secured (reg 9). This module is that
 * store:
 *
 * - One private S3 bucket (`QUARANTINE_BUCKET`), with its own access key.
 * - Every object is sealed with AES-256-GCM under `QUARANTINE_KEY`, a key
 *   used for nothing else, bound to its object name so one cannot be swapped
 *   for another.
 * - Every read, export, change and deletion appends an entry to the access
 *   log (`access/`), which holds who, what, when and the item id, never
 *   anything about the person reported.
 * - `sweep` deletes an item a year after it was detected, or a year after
 *   it was reported if that is later, and a report reference five years after
 *   the report. Expiry is done here rather than by bucket lifecycle rules
 *   because Garage has no tag-filtered lifecycle and a reported item must
 *   outlive an unreported one.
 *
 * Nothing here submits a report. The admin page prepares the fields; James
 * submits them on the NCA portal and records the reference back here.
 *
 * Layout in the bucket:
 *
 *   items/<id>/record     sealed JSON: QuarantineRecord
 *   items/<id>/content    sealed bytes: the file as received
 *   items/<id>/relevant/<part>  sealed JSON: relevant data added by an app
 *                         after the match (the website's archive, cases and
 *                         tickets for a bot match)
 *   items/<id>/submitted  sealed JSON: the report as submitted to the NCA
 *   references/<id>       sealed JSON: QuarantineReference
 *   access/<yyyy>/<mm>/<time>-<rand>.json   plain JSON: AccessEntry
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes, } from "crypto";
import { DeleteObjectCommand, GetObjectCommand, ListObjectsV2Command, PutObjectCommand, S3Client, } from "@aws-sdk/client-s3";
import exifr from "exifr";
import sharp from "sharp";
import { ncaPayload, NcaError, submitReferral, } from "./nca.js";
const DAY_MS = 24 * 60 * 60 * 1000;
/** reg 8: content, report, basis and relevant data. */
export const RETENTION_DAYS = 365;
/** reg 8: the report reference. */
export const REFERENCE_RETENTION_DAYS = 5 * 365;
const MAGIC = Buffer.from("QZ1");
/**
 * How urgent the report is, chosen by the person preparing it:
 * `immediate_risk` a child is at immediate risk (call 999 first);
 * `serious_harm` risk of serious harm (report as soon as reasonably
 * practicable); `other` (report without undue delay).
 */
export const PRIORITIES = ["immediate_risk", "serious_harm", "other"];
/** Routes a report can come to Quark by, other than the image check. */
export const INTAKE_ROUTES = [
    "email",
    "legal_report_form",
    "support_server",
    "discord",
    "police",
    "regulator",
    "other_org",
];
export class QuarantineNotFound extends Error {
}
/** Seal bytes under the key, bound to the object name. */
export function seal(key, name, plain) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(name));
    const body = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), body]);
}
/** Open what `seal` made. Throws if the key, the name or a byte is wrong. */
export function unseal(key, name, sealed) {
    if (sealed.length < 31 || !sealed.subarray(0, 3).equals(MAGIC))
        throw new Error("Not a sealed quarantine object");
    const iv = sealed.subarray(3, 15);
    const tag = sealed.subarray(15, 31);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(tag);
    return Buffer.concat([
        decipher.update(sealed.subarray(31)),
        decipher.final(),
    ]);
}
/** A 32-byte key from base64 or hex, or an error saying what is wrong. */
export function parseKey(raw) {
    const text = raw.trim();
    const key = /^[0-9a-f]{64}$/i.test(text)
        ? Buffer.from(text, "hex")
        : Buffer.from(text, "base64");
    if (key.length !== 32)
        throw new Error("QUARANTINE_KEY must be 32 bytes, as 64 hex characters or base64");
    return key;
}
const addDays = (iso, days) => new Date(Date.parse(iso) + days * DAY_MS).toISOString();
const later = (a, b) => (Date.parse(a) >= Date.parse(b) ? a : b);
async function bodyBytes(body) {
    if (!body)
        return Buffer.alloc(0);
    if (Buffer.isBuffer(body))
        return body;
    if (body instanceof Uint8Array)
        return Buffer.from(body);
    if (typeof body.transformToByteArray === "function")
        return Buffer.from(await body.transformToByteArray());
    const chunks = [];
    for await (const chunk of body)
        chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
}
const notFound = (error) => error?.name === "NoSuchKey" ||
    error?.name === "NotFound" ||
    error?.$metadata?.httpStatusCode === 404;
export class Quarantine {
    constructor({ client, bucket, key, now = () => new Date(), }) {
        if (key.length !== 32)
            throw new Error("The quarantine key must be 32 bytes");
        this.client = client;
        this.bucket = bucket;
        this.key = key;
        this.now = now;
    }
    /* ---------------- objects ---------------- */
    async putSealed(name, plain) {
        await this.client.send(new PutObjectCommand({
            Bucket: this.bucket,
            Key: name,
            Body: seal(this.key, name, plain),
            ContentType: "application/octet-stream",
        }));
    }
    async getSealed(name) {
        try {
            const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: name }));
            return unseal(this.key, name, await bodyBytes(res.Body));
        }
        catch (error) {
            if (notFound(error))
                return null;
            throw error;
        }
    }
    async remove(name) {
        await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: name }));
    }
    async listNames(prefix) {
        const names = [];
        let token;
        do {
            const res = await this.client.send(new ListObjectsV2Command({
                Bucket: this.bucket,
                Prefix: prefix,
                ContinuationToken: token,
            }));
            for (const item of res.Contents ?? [])
                if (item.Key)
                    names.push(item.Key);
            token = res.IsTruncated ? res.NextContinuationToken : undefined;
        } while (token);
        return names;
    }
    /** Append to the access log. A failure here fails the access. */
    async logAccess(entry) {
        const time = this.now().toISOString();
        const name = `access/${time.slice(0, 4)}/${time.slice(5, 7)}/${time}-${randomBytes(4).toString("hex")}.json`;
        await this.client.send(new PutObjectCommand({
            Bucket: this.bucket,
            Key: name,
            Body: JSON.stringify({ time, ...entry }),
            ContentType: "application/json",
        }));
    }
    /** The access log, newest first, up to `limit` entries. */
    async accessLog(actor, limit = 200) {
        const names = (await this.listNames("access/")).sort().reverse();
        const entries = [];
        for (const name of names.slice(0, limit)) {
            const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: name }));
            entries.push(JSON.parse((await bodyBytes(res.Body)).toString("utf8")));
        }
        await this.logAccess({ actor, action: "read", detail: "access log" });
        return entries;
    }
    /* ---------------- items ---------------- */
    /** Keep a matched file and its data. Resolves with the item's id. */
    async put(input) {
        const at = this.now();
        const id = `${at.getTime().toString(36)}-${randomBytes(6).toString("hex")}`;
        const detectedAt = at.toISOString();
        const record = {
            id,
            version: 1,
            detected_at: detectedAt,
            source: input.detection.source ?? "unknown",
            detection: input.detection,
            content: {
                stored: !!input.content,
                bytes: input.content?.length ?? 0,
                sha256: input.content ? createHash("sha256").update(input.content).digest("hex") : "",
                type: input.contentType,
                name: input.fileName,
            },
            subject: input.subject,
            relevant_data: input.relevantData,
            relevant_data_error: input.relevantDataError,
            intake: input.intake,
            expires_at: addDays(detectedAt, RETENTION_DAYS),
        };
        // Content first: a record never points at content that was not written.
        if (input.content)
            await this.putSealed(`items/${id}/content`, input.content);
        await this.putSealed(`items/${id}/record`, Buffer.from(JSON.stringify(record)));
        await this.logAccess({
            actor: input.intake ? input.intake.recorded_by : `system:${record.source}`,
            action: input.intake ? "intake" : "write",
            id,
            detail: input.intake
                ? `${input.intake.route}${input.detection.guild_id ? ` guild ${input.detection.guild_id}` : ""}`
                : `${input.detection.category}${input.detection.guild_id ? ` guild ${input.detection.guild_id}` : ""}`,
        });
        return id;
    }
    async readRecord(id) {
        if (!/^[a-z0-9]+-[0-9a-f]{12}$/.test(id))
            throw new QuarantineNotFound(id);
        const plain = await this.getSealed(`items/${id}/record`);
        if (!plain)
            throw new QuarantineNotFound(id);
        return JSON.parse(plain.toString("utf8"));
    }
    async recordIds() {
        return (await this.listNames("items/"))
            .filter((name) => name.endsWith("/record"))
            .map((name) => name.slice("items/".length, -"/record".length));
    }
    /** Every item, newest first, without the relevant data or the file. */
    async list(actor) {
        const ids = (await this.recordIds()).sort().reverse();
        const records = [];
        for (const id of ids) {
            try {
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                const { relevant_data, ...summary } = await this.readRecord(id);
                records.push(summary);
            }
            catch (error) {
                if (!(error instanceof QuarantineNotFound))
                    throw error;
            }
        }
        await this.logAccess({ actor, action: "list", detail: `${records.length} items` });
        return records;
    }
    /** One item's record, with its relevant data and the report as submitted. Not the file. */
    async get(id, actor) {
        const item = await this.readItem(id);
        await this.logAccess({ actor, action: "read", id });
        return item;
    }
    async readItem(id) {
        const record = await this.readRecord(id);
        const parts = {};
        for (const name of await this.listNames(`items/${id}/relevant/`)) {
            const plain = await this.getSealed(name);
            if (plain)
                parts[name.slice(`items/${id}/relevant/`.length)] = JSON.parse(plain.toString("utf8"));
        }
        const submitted = await this.getSealed(`items/${id}/submitted`);
        return {
            ...record,
            relevant_data_parts: parts,
            submitted: submitted ? JSON.parse(submitted.toString("utf8")) : undefined,
        };
    }
    /**
     * Add relevant data to an item after the match, under a name: the website
     * adds what it holds (archive rows, cases, tickets) to a bot's match.
     */
    async addRelevantData(id, part, data, actor) {
        if (!/^[a-z0-9-]{1,32}$/.test(part))
            throw new Error("Bad part name");
        await this.readRecord(id);
        await this.putSealed(`items/${id}/relevant/${part}`, Buffer.from(JSON.stringify(data)));
        await this.logAccess({ actor, action: "add_relevant_data", id, detail: part });
    }
    /** How urgent the report is. */
    async setPriority(id, level, actor) {
        if (!PRIORITIES.includes(level))
            throw new Error("Unknown priority");
        const record = await this.readRecord(id);
        record.priority = {
            level,
            set_by: actor,
            set_at: this.now().toISOString(),
        };
        await this.writeRecord(record);
        await this.logAccess({ actor, action: "set_priority", id, detail: level });
        return record;
    }
    /**
     * Keep an item (and its report reference) past its time for a
     * law-enforcement request, with the reason; `null` lifts the hold and the
     * item expires at its usual time.
     */
    async setHold(id, reason, actor) {
        const record = await this.readRecord(id);
        const clean = reason?.trim() ?? "";
        if (reason !== null && (!clean || clean.length > 500))
            throw new Error("The reason must be 1 to 500 characters");
        record.hold = reason === null
            ? undefined
            : { reason: clean, set_by: actor, set_at: this.now().toISOString() };
        await this.writeRecord(record);
        const refName = `references/${id}`;
        const plain = await this.getSealed(refName);
        if (plain) {
            const kept = JSON.parse(plain.toString("utf8"));
            kept.hold = record.hold;
            await this.putSealed(refName, Buffer.from(JSON.stringify(kept)));
        }
        await this.logAccess({
            actor,
            action: "set_hold",
            id,
            detail: reason === null ? "lifted" : "set",
        });
        return record;
    }
    /**
     * Delete an item that is not to be reported: the database's
     * `harmful-abusive-material`, a recorded report found not to be CSEA, a
     * match judged a false positive by the NCA or the police. Everything
     * stored for it goes; the access log keeps who deleted it, when and why.
     *
     * Refused for an item already reported (regulation 8 keeps it a year from
     * the report) and for one on legal hold.
     */
    async deleteUnreported(id, reason, actor) {
        const record = await this.readRecord(id);
        if (record.report)
            throw new Error("Reported items are kept for one year from the report and cannot be deleted");
        if (record.hold)
            throw new Error("This item is on legal hold. Lift the hold first");
        const clean = reason.trim();
        if (!clean || clean.length > 500)
            throw new Error("The reason must be 1 to 500 characters");
        for (const name of await this.listNames(`items/${id}/`))
            if (name !== `items/${id}/record`)
                await this.remove(name);
        await this.remove(`items/${id}/record`);
        await this.logAccess({ actor, action: "delete_unreported", id, detail: clean });
    }
    async writeRecord(record) {
        await this.putSealed(`items/${record.id}/record`, Buffer.from(JSON.stringify(record)));
    }
    /**
     * The fields a report needs (Schedule 1, "where available"), as one
     * object. Logged as an export.
     */
    async reportFields(id, actor, app = {}) {
        const item = await this.readItem(id);
        const fields = await this.fieldsFor(item, app);
        await this.logAccess({ actor, action: "export_fields", id });
        return fields;
    }
    /**
     * Everything the report's fields are made from that is not in the record:
     * earlier reports about the same user or image, and the file's EXIF.
     */
    async fieldsFor(item, app = {}) {
        const content = await this.getSealed(`items/${item.id}/content`);
        return reportFieldsOf(item, {
            ...app,
            previousReports: await this.previousReports(item),
            exif: content ? await exifOf(content) : { error: "the file is not held" },
        });
    }
    /**
     * Reports already sent that this one relates to (Schedule 1: "whether it
     * relates to a previous report"): the same Discord user, or the same image
     * by its PDQ hash. Read from the kept references, which outlive their
     * items. References made before `user_id` was kept match by image only,
     * unless their item is still here to say who it was about.
     */
    async previousReports(item) {
        const userId = item.subject.user_id ?? item.detection.user_id;
        const out = [];
        for (const name of await this.listNames("references/")) {
            const plain = await this.getSealed(name);
            if (!plain)
                continue;
            const kept = JSON.parse(plain.toString("utf8"));
            if (kept.id === item.id)
                continue;
            let keptUser = kept.user_id;
            if (!keptUser) {
                try {
                    const other = await this.readRecord(kept.id);
                    keptUser = other.subject.user_id ?? other.detection.user_id;
                }
                catch (error) {
                    if (!(error instanceof QuarantineNotFound))
                        throw error;
                }
            }
            const sameUser = !!userId && keptUser === userId;
            const sameImage = !!kept.pdq && kept.pdq === item.detection.pdq;
            if (!sameUser && !sameImage)
                continue;
            out.push({
                reference: kept.reference,
                reported_at: kept.reported_at,
                quarantine_id: kept.id,
                relates_by: sameUser && sameImage ? "same user and image" : sameUser ? "same user" : "same image",
            });
        }
        return out.sort((a, b) => a.reported_at.localeCompare(b.reported_at));
    }
    /**
     * Stop (reason) or allow (null) automatic reporting of one item. A report
     * an admin submits by hand is not affected.
     */
    async setAutoReport(id, pausedReason, actor) {
        const record = await this.readRecord(id);
        const clean = pausedReason?.trim() ?? "";
        if (pausedReason !== null && (!clean || clean.length > 500))
            throw new Error("The reason must be 1 to 500 characters");
        record.nca = {
            ...record.nca,
            paused: pausedReason === null ? undefined : { reason: clean, set_by: actor, set_at: this.now().toISOString() },
        };
        await this.writeRecord(record);
        await this.logAccess({ actor, action: "set_auto_report", id, detail: pausedReason === null ? "allowed" : `paused: ${clean}` });
        return record;
    }
    /**
     * Why an item is not reported automatically, or null when it should be.
     * `others` are the other items, to find one that already covers the same
     * file (the same attachment matched when stored and again before re-upload).
     */
    autoReportBlocker(record, others = []) {
        if (record.report)
            return "already reported";
        if (record.nca?.paused)
            return `paused: ${record.nca.paused.reason}`;
        if (record.nca?.error?.permanent)
            return `the NCA refused it: ${record.nca.error.message}`;
        if (record.intake && !record.intake.auto_report)
            return "recorded for a decision by hand";
        if (!record.intake && record.detection.category !== "csam")
            return `classified ${record.detection.category}: decide by hand whether it is reportable`;
        const attachment = record.subject.attachment_id ?? record.detection.attachment_id;
        if (attachment) {
            const earlier = others.find((o) => o.id !== record.id &&
                (o.subject.attachment_id ?? o.detection.attachment_id) === attachment &&
                (o.report || o.detected_at < record.detected_at));
            if (earlier)
                return `same file as ${earlier.id}`;
        }
        return null;
    }
    /**
     * Report one item to the NCA through the API: the fields, a JSON document
     * with everything else held, and the file itself, sent from here. The
     * reference is then recorded as for any report. Throws `NcaError`; a 400
     * is kept on the item so it is not tried again automatically.
     */
    async submitToNca(id, actor, config, app = {}) {
        const record = await this.readRecord(id);
        if (record.report)
            throw new Error(`Already reported (${record.report.reference})`);
        const item = await this.readItem(id);
        const fields = await this.fieldsFor(item, app);
        const payload = ncaPayload(item, fields, config);
        const files = [];
        if (record.content.stored) {
            const content = await this.getSealed(`items/${id}/content`);
            if (content)
                files.push({
                    name: record.content.name || `quarantine-${id}`,
                    type: record.content.type || "application/octet-stream",
                    bytes: content,
                });
        }
        files.push({
            name: "quark-report.json",
            type: "application/json",
            bytes: Buffer.from(JSON.stringify(fields, null, 2)),
        });
        const at = this.now().toISOString();
        record.nca = { ...record.nca, attempts: (record.nca?.attempts ?? 0) + 1, last_attempt_at: at };
        let result;
        try {
            result = await submitReferral(config, payload, files);
        }
        catch (error) {
            const permanent = error instanceof NcaError && error.permanent;
            const message = error?.message?.slice(0, 500) ?? String(error);
            record.nca.error = { message, permanent, at };
            await this.writeRecord(record);
            await this.logAccess({ actor, action: "submit_nca_failed", id, detail: message.slice(0, 200) });
            throw error;
        }
        record.nca.error = undefined;
        await this.writeRecord(record);
        await this.logAccess({ actor, action: "submit_nca", id, detail: result.referralFriendlyID });
        const reported = await this.recordReport(id, {
            reference: result.referralFriendlyID,
            reportedAt: at,
            submitted: { via: "api", payload, fields, files: files.map((f) => ({ name: f.name, bytes: f.bytes.length })) },
            viaApi: { referral_id: result.referralID, report_id: result.reportID },
        }, actor);
        return { record: reported, result };
    }
    /**
     * Record the NCA's reference for a submitted report. The item is then kept
     * at least a year from the report date, and the reference five years.
     */
    async recordReport(id, { reference, reportedAt, submitted, viaApi, }, actor) {
        const cleanReference = reference.trim();
        if (!cleanReference || cleanReference.length > 200)
            throw new Error("The reference must be 1 to 200 characters");
        const reported = new Date(reportedAt);
        if (Number.isNaN(reported.getTime()) || reported > this.now())
            throw new Error("The report date must be a date that has passed");
        const record = await this.readRecord(id);
        const reportedIso = reported.toISOString();
        record.report = {
            reference: cleanReference,
            reported_at: reportedIso,
            recorded_by: actor,
            recorded_at: this.now().toISOString(),
            ...(viaApi ? { via_api: viaApi } : {}),
        };
        record.expires_at = later(record.expires_at, addDays(reportedIso, RETENTION_DAYS));
        const kept = {
            id,
            reference: cleanReference,
            reported_at: reportedIso,
            detected_at: record.detected_at,
            category: record.detection.category,
            pdq: record.detection.pdq,
            user_id: record.subject.user_id ?? record.detection.user_id,
            expires_at: addDays(reportedIso, REFERENCE_RETENTION_DAYS),
        };
        kept.hold = record.hold;
        const asSubmitted = submitted ?? (await this.fieldsFor(await this.readItem(id)));
        await this.putSealed(`items/${id}/submitted`, Buffer.from(JSON.stringify({
            reference: cleanReference,
            reported_at: reportedIso,
            report: asSubmitted,
        })));
        await this.putSealed(`references/${id}`, Buffer.from(JSON.stringify(kept)));
        await this.writeRecord(record);
        await this.logAccess({
            actor,
            action: "record_report",
            id,
            detail: cleanReference,
        });
        return record;
    }
    /** Report references still kept, including those whose item has gone. */
    async references(actor) {
        const out = [];
        for (const name of await this.listNames("references/")) {
            const plain = await this.getSealed(name);
            if (plain)
                out.push(JSON.parse(plain.toString("utf8")));
        }
        await this.logAccess({ actor, action: "read", detail: "references" });
        return out;
    }
    /**
     * Delete what has passed its time: items a year after detection (or after
     * the report, if later), references five years after the report, and access
     * log entries five years old. Run daily by the bots. Each deletion is logged.
     */
    async sweep(actor = "system:sweep") {
        const now = this.now();
        let items = 0;
        let references = 0;
        let accessEntries = 0;
        for (const id of await this.recordIds()) {
            let record;
            try {
                record = await this.readRecord(id);
            }
            catch (error) {
                if (error instanceof QuarantineNotFound)
                    continue;
                throw error;
            }
            if (record.hold || Date.parse(record.expires_at) > now.getTime())
                continue;
            // The record last, so an interrupted sweep is finished next time.
            for (const name of await this.listNames(`items/${id}/`))
                if (name !== `items/${id}/record`)
                    await this.remove(name);
            await this.remove(`items/${id}/record`);
            await this.logAccess({ actor, action: "expire", id });
            items++;
        }
        for (const name of await this.listNames("references/")) {
            const plain = await this.getSealed(name);
            if (!plain)
                continue;
            const kept = JSON.parse(plain.toString("utf8"));
            if (kept.hold || Date.parse(kept.expires_at) > now.getTime())
                continue;
            await this.remove(name);
            await this.logAccess({ actor, action: "expire_reference", id: kept.id });
            references++;
        }
        const cutoff = new Date(now.getTime() - REFERENCE_RETENTION_DAYS * DAY_MS)
            .toISOString()
            .slice(0, 7);
        for (const name of await this.listNames("access/")) {
            const month = name.slice("access/".length, "access/".length + 7).replace("/", "-");
            if (month < cutoff) {
                await this.remove(name);
                accessEntries++;
            }
        }
        return { items, references, accessEntries };
    }
}
/** A snowflake's creation time, or undefined. */
function snowflakeTime(id) {
    if (!id || !/^\d{17,20}$/.test(id))
        return undefined;
    return new Date(Number((BigInt(id) >> 22n) + 1420070400000n)).toISOString();
}
const PRIORITY_TEXT = {
    immediate_risk: "A child is at immediate risk: call 999 first, then report",
    serious_harm: "Risk of serious harm: report as soon as reasonably practicable",
    other: "Report without undue delay",
};
/**
 * The file's EXIF (Schedule 1: "linked exif data"): readable tags, GPS
 * included, and the raw block so nothing is lost in reading it. Discord
 * strips some of it from uploads, so `tags: null` is a normal answer.
 */
export async function exifOf(content) {
    let raw;
    try {
        raw = (await sharp(content, { animated: false }).metadata()).exif;
    }
    catch {
        // Not an image sharp reads; exifr may still find a block.
    }
    try {
        const tags = (await exifr.parse(content, {
            tiff: true,
            exif: true,
            gps: true,
            ifd1: false,
            interop: false,
            xmp: false,
            icc: false,
            iptc: false,
            jfif: false,
            ihdr: false,
            makerNote: false,
            userComment: true,
            translateValues: true,
            reviveValues: true,
        }));
        return {
            tags: tags && Object.keys(tags).length ? jsonSafe(tags) : null,
            raw_base64: raw?.length ? raw.toString("base64") : null,
        };
    }
    catch (error) {
        return raw?.length
            ? { tags: null, raw_base64: raw.toString("base64") }
            : { error: `could not be read: ${error.message}` };
    }
}
/** Dates as ISO strings, bytes as base64, so the tags survive JSON. */
function jsonSafe(value) {
    const out = {};
    for (const [key, v] of Object.entries(value)) {
        if (v instanceof Date)
            out[key] = Number.isNaN(v.getTime()) ? null : v.toISOString();
        else if (v instanceof Uint8Array)
            out[key] = Buffer.from(v).toString("base64");
        else
            out[key] = v;
    }
    return out;
}
const SNOWFLAKE = /^\d{17,20}$/;
/** The Discord link to the message the file was posted in, when all three ids are known. */
function messageUrl(guild, channel, message) {
    return guild && channel && message && [guild, channel, message].every((id) => SNOWFLAKE.test(id))
        ? `https://discord.com/channels/${guild}/${channel}/${message}`
        : null;
}
/** The quark.bot address a dashboard upload was sent to. */
function uploadUrl(route) {
    return route && route.startsWith("/") ? `https://quark.bot${route}` : null;
}
/**
 * The report's fields from an item: Schedule 1, "where available", in the
 * order the report is made (reporter, urgency, the user, the content and how
 * it was found, where and when, the relevant data). What Quark does not hold
 * is named under `not_available` rather than left out silently.
 *
 * `extra` is what is not in the record: earlier reports and the EXIF (read
 * by the store), and billing records (from the app, which holds them).
 */
export function reportFieldsOf(item, extra = {}) {
    const s = item.subject;
    const d = item.detection;
    const userId = s.user_id ?? d.user_id;
    const guildId = s.guild_id ?? d.guild_id;
    const channelId = s.channel_id ?? d.channel_id;
    const billing = extra.billing;
    const billingHas = (key) => !!billing?.some((b) => b[key] || b.payment_methods?.some((m) => m[key]));
    const notAvailable = [];
    if (!s.ip)
        notAvailable.push(item.source === "dashboard"
            ? "IP address: not received with this upload"
            : "IP address: not available. Discord does not give bots the IP address of the person who posted");
    notAvailable.push("Port number: not recorded", "Registration and login IP addresses: not held. Quark keeps only a one-way hash of the addresses used to sign in to its dashboard", "Date of birth: not held");
    if (extra.billingError)
        notAvailable.push(`Billing details: could not be checked (${extra.billingError})`);
    else if (billing === undefined)
        notAvailable.push("Billing details: not checked");
    else if (!billing.length)
        notAvailable.push("Billing name, address, email and phone: the user has never paid Quark. Discord does not give bots email addresses or phone numbers");
    else {
        if (!billingHas("email"))
            notAvailable.push("Email address: not on the user's billing records");
        if (!billingHas("phone"))
            notAvailable.push("Telephone number: not on the user's billing records");
    }
    if (!userId)
        notAvailable.push("Discord account: not known for this file");
    if (!s.guild_name)
        notAvailable.push("Server name: not known at the time");
    if (extra.exif && "tags" in extra.exif && !extra.exif.tags && !extra.exif.raw_base64)
        notAvailable.push("EXIF data: none in the file");
    const parts = "relevant_data_parts" in item ? item.relevant_data_parts : {};
    const previous = extra.previousReports ?? [];
    return {
        "1_reporting_service": {
            name: "Quark",
            description: "Discord bot that logs server activity, and its dashboard at quark.bot",
        },
        "2_priority": item.priority
            ? { level: item.priority.level, meaning: PRIORITY_TEXT[item.priority.level] }
            : { level: null, meaning: "Not chosen yet" },
        "3_user": {
            discord_user_id: userId ?? null,
            username: s.username ?? null,
            display_name: s.display_name ?? null,
            profile_url: userId && SNOWFLAKE.test(userId) ? `https://discord.com/users/${userId}` : null,
            account_created_at: snowflakeTime(userId) ?? null,
            ip_address: s.ip ?? null,
            ip_address_time: s.ip ? d.time : null,
            user_agent: s.user_agent ?? null,
            billing: extra.billingError ? null : (billing ?? null),
        },
        "4_content": {
            description: item.intake
                ? item.content.stored
                    ? `Quark's stored copy of the reported file, kept without being viewed. Reported to Quark via ${item.intake.route}: ${item.intake.summary ?? ""}`
                    : `Reported to Quark via ${item.intake.route}: ${item.intake.summary ?? ""}. Quark holds no copy of the file.`
                : "Image file matched against known material by perceptual hash. Not viewed by Quark.",
            file_type: item.content.type ?? null,
            file_name: item.content.name ?? null,
            size_bytes: item.content.bytes,
            sha256: item.content.sha256,
            exif: extra.exif ?? null,
            held: item.content.stored
                ? "Kept encrypted in Quark's restricted store, and sent with this report straight from it."
                : "Not held by Quark.",
        },
        "5_how_detected": {
            method: item.intake
                ? `Reported to Quark (${item.intake.route}${item.intake.reporter ? `, by ${item.intake.reporter}` : ""}${item.intake.reference ? `, their reference ${item.intake.reference}` : ""}). Not matched by Quark's image check.`
                : "PDQ perceptual hash computed by Quark and matched by Project Arachnid Shield (Canadian Centre for Child Protection). Only the hash was sent.",
            provider: d.provider,
            classification: d.category,
            match_type: d.match_type,
            matched_entry: d.reference ?? null,
            match_response: d.match_details ?? null,
            pdq_hash_hex: Buffer.from(d.pdq, "base64").toString("hex"),
            pdq_hash_base64: d.pdq,
            frame: d.frame ?? 0,
            frames: d.frames ?? null,
            all_frame_hashes_base64: d.hashes ?? [d.pdq],
        },
        "6_when_and_where": {
            posted_or_uploaded_at: d.time,
            detected_at: item.detected_at,
            where: item.intake
                ? guildId
                    ? "In a Discord server that uses Quark, as reported to Quark"
                    : "As reported to Quark"
                : d.stage === "upload"
                    ? `Upload to the quark.bot dashboard${s.route ? ` (${s.route})` : ""}`
                    : d.stage === "store"
                        ? "Attachment posted in a Discord server, checked when Quark stored it for its logs"
                        : "Attachment stored by Quark, checked before Quark re-posted it in a log",
            url: item.intake
                ? messageUrl(guildId, channelId, s.message_id)
                : d.stage === "upload"
                    ? uploadUrl(s.route)
                    : messageUrl(guildId, channelId, s.message_id),
            discord_server_id: guildId ?? null,
            discord_server_name: s.guild_name ?? null,
            discord_channel_id: channelId ?? null,
            discord_message_id: s.message_id ?? null,
            discord_attachment_id: s.attachment_id ?? d.attachment_id ?? null,
        },
        "7_relevant_data_two_weeks": {
            at_match: item.relevant_data ?? null,
            at_match_error: item.relevant_data_error ?? null,
            added_since: parts,
        },
        "8_previous_reports": {
            relates_to_previous_report: previous.length > 0,
            reports: previous,
        },
        not_available: notAvailable,
        quarantine_id: item.id,
        report: item.report ?? null,
    };
}
/**
 * The store from the environment, or undefined when it is not configured.
 *
 *   QUARANTINE_BUCKET                 the private bucket
 *   QUARANTINE_KEY                    32 bytes, hex or base64; nothing else uses it
 *   QUARANTINE_S3_URL                 endpoint, else S3_URI
 *   QUARANTINE_S3_REGION              else S3_REGION, else "garage"
 *   QUARANTINE_S3_ACCESS_KEY_ID       else S3_ACCESS_KEY_ID
 *   QUARANTINE_S3_SECRET_ACCESS_KEY   else S3_ACCESS_KEY_SECRET
 *
 * A key for this bucket alone is the intent; the fallbacks exist so a bot pod
 * that already has S3 credentials can be pointed at the bucket while that key
 * is made.
 */
export function quarantineFromEnv(env = process.env) {
    const bucket = env.QUARANTINE_BUCKET;
    const rawKey = env.QUARANTINE_KEY;
    const endpoint = env.QUARANTINE_S3_URL || env.S3_URI;
    const accessKeyId = env.QUARANTINE_S3_ACCESS_KEY_ID || env.S3_ACCESS_KEY_ID;
    const secretAccessKey = env.QUARANTINE_S3_SECRET_ACCESS_KEY || env.S3_ACCESS_KEY_SECRET;
    if (!bucket || !rawKey || !endpoint || !accessKeyId || !secretAccessKey)
        return undefined;
    let key;
    try {
        key = parseKey(rawKey);
    }
    catch (error) {
        console.error(`[FILE SCAN] QUARANTINE OFF: ${error.message}`);
        return undefined;
    }
    return new Quarantine({
        client: new S3Client({
            endpoint,
            region: env.QUARANTINE_S3_REGION || env.S3_REGION || "garage",
            forcePathStyle: true,
            credentials: { accessKeyId, secretAccessKey },
        }),
        bucket,
        key,
    });
}
export * from "./nca.js";
//# sourceMappingURL=index.js.map