import type { Detection } from "../scan/scanner.js";
import { type NcaConfig, type NcaResult } from "./nca.js";
/** reg 8: content, report, basis and relevant data. */
export declare const RETENTION_DAYS = 365;
/** reg 8: the report reference. */
export declare const REFERENCE_RETENTION_DAYS: number;
/** The report register: six years from a case's last change. */
export declare const REGISTER_RETENTION_DAYS: number;
/** Who sent it and from where, as far as the app that found it knows. */
export interface QuarantineSubject {
    /** Discord user id. */
    user_id?: string;
    username?: string;
    display_name?: string;
    guild_id?: string;
    guild_name?: string;
    channel_id?: string;
    message_id?: string;
    attachment_id?: string;
    /** Dashboard uploads only: the client IP from the site's trusted header. */
    ip?: string;
    user_agent?: string;
    /** Dashboard uploads only: the route it was sent to. */
    route?: string;
}
/**
 * How urgent the report is, chosen by the person preparing it:
 * `immediate_risk` a child is at immediate risk (call 999 first);
 * `serious_harm` risk of serious harm (report as soon as reasonably
 * practicable); `other` (report without undue delay).
 */
export declare const PRIORITIES: readonly ["immediate_risk", "serious_harm", "other"];
export type Priority = (typeof PRIORITIES)[number];
export interface QuarantineRecord {
    id: string;
    version: 1;
    detected_at: string;
    source: NonNullable<Detection["source"]> | "unknown";
    detection: Detection;
    content: {
        stored: boolean;
        bytes: number;
        sha256: string;
        type?: string;
        name?: string;
        /** Set when the file held is shorter than the size Discord declared. */
        declared_bytes?: number;
    };
    subject: QuarantineSubject;
    /** The user's relevant data from the two weeks before, as the app held it. */
    relevant_data?: unknown;
    relevant_data_error?: string;
    /** When `sweep` deletes the item, unless it is on hold. */
    expires_at: string;
    priority?: {
        level: Priority;
        set_by: string;
        set_at: string;
    };
    /** Kept past its time: a law-enforcement request. Cleared to let it expire. */
    hold?: {
        reason: string;
        set_by: string;
        set_at: string;
    };
    report?: {
        reference: string;
        reported_at: string;
        recorded_by: string;
        recorded_at: string;
        /** Set when it went through the API: the NCA's own ids. */
        via_api?: {
            referral_id: string;
            report_id?: number;
        };
        /** Sent without the file (e.g. the NCA's service refused its bytes), and why. */
        file_not_sent?: string;
        /**
         * The NCA said the report's media did not all upload (their email "Some
         * media files have not uploaded"). Cleared by a supplementary report.
         */
        media_missing?: {
            note: string;
            set_by: string;
            set_at: string;
        };
    };
    /**
     * Sent to the NCA as other relevant information (reg. 6(4)(d)) with the
     * report on another item from the same uploader: a `harmful-abusive-material`
     * match attached to a `csam` report. Kept a year from that report.
     */
    included_in?: {
        item: string;
        reference: string;
        at: string;
    };
    /** Supplementary reports (SI 2026/268 reg. 6(5)), oldest first. */
    supplementary?: Array<{
        reference: string;
        reported_at: string;
        reason: string;
        referral_id?: string;
    }>;
    /** How it came to Quark when not from the image check. */
    intake?: Intake;
    /** Automatic reporting to the NCA (`autoReportBlocker`). */
    nca?: {
        /** Set by an admin: do not report automatically, and why. */
        paused?: {
            reason: string;
            set_by: string;
            set_at: string;
        };
        attempts?: number;
        last_attempt_at?: string;
        /**
         * The last failure. `permanent`: not tried again automatically, because
         * the NCA refused it or because it may have been received (`uncertain`).
         */
        error?: {
            message: string;
            permanent: boolean;
            uncertain?: boolean;
            local?: boolean;
            at: string;
        };
        /** Another report already covers this file (same attachment). */
        covered_by?: string;
    };
}
/** Routes a report can come to Quark by, other than the image check. */
export declare const INTAKE_ROUTES: readonly ["email", "legal_report_form", "support_server", "discord", "police", "regulator", "other_org"];
export type IntakeRoute = (typeof INTAKE_ROUTES)[number];
export interface Intake {
    route: IntakeRoute;
    /** Who reported it, as they gave it (a name, an address, "anonymous"). */
    reporter?: string;
    /** Their reference, e.g. a police case number. */
    reference?: string;
    /** One neutral sentence: what was alleged. */
    summary?: string;
    recorded_by: string;
    recorded_at: string;
    /** Report to the NCA without waiting for an admin. */
    auto_report: boolean;
}
/** What is listed on the admin page: everything but the relevant data. */
export type QuarantineSummary = Omit<QuarantineRecord, "relevant_data">;
/** One item with everything added to it since. */
export type QuarantineItem = QuarantineRecord & {
    /** Parts added after the match, by name (`website`, ...). */
    relevant_data_parts: Record<string, unknown>;
    /** The report as it was submitted, once it has been. */
    submitted?: unknown;
};
export interface QuarantineReference {
    id: string;
    reference: string;
    reported_at: string;
    detected_at: string;
    category: string;
    pdq: string;
    /** Who it was about, so a later report can say it relates to this one. */
    user_id?: string;
    /** Where, so a later report from the same server can name this one. */
    guild_id?: string;
    expires_at: string;
    hold?: QuarantineRecord["hold"];
    /** References of supplementary reports, kept as long as this one. */
    supplementary?: string[];
}
export interface AccessEntry {
    time: string;
    /** `admin:<discord id>`, or `system:<what>` for the apps themselves. */
    actor: string;
    action: "write" | "list" | "read" | "export_fields" | "export_content" | "record_report" | "set_priority" | "set_hold" | "add_relevant_data" | "expire" | "expire_reference" | "intake" | "submit_nca" | "submit_nca_failed" | "submit_nca_supplementary" | "mark_media_missing" | "include_in_report" | "set_auto_report" | "delete_unreported" | "set_nca_api_key" | "check_nca" | "write_register" | "expire_register";
    id?: string;
    detail?: string;
}
/**
 * One item in a register case: identifiers and what happened to it. Never
 * content: no file, no relevant data.
 */
export interface RegisterItem {
    quarantine_id: string;
    detected_at: string;
    category: string;
    stage?: string;
    pdq?: string;
    guild_id?: string;
    channel_id?: string;
    message_id?: string;
    attachment_id?: string;
    user_id?: string;
    outcome: "pending" | "reported" | "cleared";
    /** The NCA reference, for a reported item. */
    reference?: string;
    /** When it was reported or cleared. */
    at?: string;
    /** Why it was cleared without a report. */
    reason?: string;
}
/**
 * One line of the report register (procedure section 7): a case of one or
 * more quarantined items that belong together, written by the app and kept
 * after the items themselves are deleted. Identifiers only.
 */
export interface RegisterEntry {
    id: string;
    opened_at: string;
    updated_at: string;
    /** "image check", or the intake route. */
    route: string;
    reporter: string;
    type: "A";
    /** One neutral sentence. */
    allegation: string;
    items: RegisterItem[];
    notes?: string;
}
/** The NCA API key as entered on the admin page. Never sent back to a page. */
export interface NcaApiKeyRecord {
    api_key: string;
    set_at: string;
    set_by: string;
    /** When the NCA says the key stops working (they last six months). */
    expires_at: string;
    /** Reminders already sent, in days before expiry (0 = expired). */
    reminded: number[];
}
/** What a page may see of the stored key. */
export interface NcaApiKeyStatus {
    set_at: string;
    set_by: string;
    expires_at: string;
    last4: string;
}
export interface PutInput {
    detection: Detection;
    /** The file; null for a report with no file Quark still holds. */
    content: Buffer | null;
    contentType?: string;
    fileName?: string;
    /** The size Discord declared; recorded when the file is shorter. */
    declaredBytes?: number;
    subject: QuarantineSubject;
    relevantData?: unknown;
    relevantDataError?: string;
    intake?: Intake;
}
/** The part of an S3 client this needs; tests pass a map. */
export interface ObjectClient {
    send(command: unknown): Promise<any>;
}
export declare class QuarantineNotFound extends Error {
}
/** Seal bytes under the key, bound to the object name. */
export declare function seal(key: Buffer, name: string, plain: Buffer): Buffer;
/** Open what `seal` made. Throws if the key, the name or a byte is wrong. */
export declare function unseal(key: Buffer, name: string, sealed: Buffer): Buffer;
/** A 32-byte key from base64 or hex, or an error saying what is wrong. */
export declare function parseKey(raw: string): Buffer;
export declare class Quarantine {
    private client;
    private bucket;
    private key;
    private now;
    constructor({ client, bucket, key, now, }: {
        client: ObjectClient;
        bucket: string;
        /** 32 bytes. */
        key: Buffer;
        now?: () => Date;
    });
    private putSealed;
    private getSealed;
    private remove;
    private listNames;
    /** Append to the access log. A failure here fails the access. */
    logAccess(entry: Omit<AccessEntry, "time">): Promise<void>;
    /** The access log, newest first, up to `limit` entries. */
    accessLog(actor: string, limit?: number): Promise<AccessEntry[]>;
    /**
     * Store a new NCA API key, replacing the old one. Logged, without the key.
     */
    setNcaApiKey(apiKey: string, expiresAt: Date, actor: string): Promise<NcaApiKeyStatus>;
    /** The stored key, for sending reports. Null if none was entered. */
    ncaApiKey(): Promise<NcaApiKeyRecord | null>;
    /** When and by whom the key was set, its expiry and last four characters. */
    ncaApiKeyStatus(): Promise<NcaApiKeyStatus | null>;
    /**
     * Note that the reminder for `days` before expiry was sent, so it is sent
     * once. False if the key changed since `setAt` or it was already sent.
     */
    markNcaKeyReminder(setAt: string, days: number): Promise<boolean>;
    /** Keep a matched file and its data. Resolves with the item's id. */
    put(input: PutInput): Promise<string>;
    private readRecord;
    private recordIds;
    /** Every item, newest first, without the relevant data or the file. */
    list(actor: string): Promise<QuarantineSummary[]>;
    /** One item's record, with its relevant data and the report as submitted. Not the file. */
    get(id: string, actor: string): Promise<QuarantineItem>;
    private readItem;
    /**
     * Add relevant data to an item after the match, under a name: the website
     * adds what it holds (archive rows, cases, tickets) to a bot's match.
     */
    addRelevantData(id: string, part: string, data: unknown, actor: string): Promise<void>;
    /** How urgent the report is. */
    setPriority(id: string, level: Priority, actor: string): Promise<QuarantineRecord>;
    /**
     * Keep an item (and its report reference) past its time for a
     * law-enforcement request, with the reason; `null` lifts the hold and the
     * item expires at its usual time.
     */
    setHold(id: string, reason: string | null, actor: string): Promise<QuarantineRecord>;
    /**
     * Delete an item that is not to be reported: the database's
     * `harmful-abusive-material`, a recorded report found not to be CSEA, a
     * match judged a false positive by the NCA or the police. Everything
     * stored for it goes; the access log keeps who deleted it, when and why.
     *
     * Refused for an item already reported (regulation 8 keeps it a year from
     * the report) and for one on legal hold.
     */
    deleteUnreported(id: string, reason: string, actor: string): Promise<void>;
    private writeRecord;
    /**
     * The fields a report needs (Schedule 1, "where available"), as one
     * object. Logged as an export.
     */
    reportFields(id: string, actor: string, app?: AppReportData): Promise<{
        "1_reporting_service": {
            name: string;
            description: string;
        };
        "2_priority": {
            level: "immediate_risk" | "serious_harm" | "other";
            meaning: string;
        } | {
            level: null;
            meaning: string;
        };
        "3_user": {
            discord_user_id: string | null;
            username: string | null;
            display_name: string | null;
            profile_url: string | null;
            account_created_at: string | null;
            ip_address: string | null;
            ip_address_time: string | null;
            user_agent: string | null;
            billing: BillingRecord[] | null;
        };
        "4_content": {
            description: string;
            file_type: string | null;
            file_name: string | null;
            size_bytes: number;
            sha256: string;
            exif: ExifResult | null;
            held: string;
        };
        "5_how_detected": {
            method: string;
            provider: string;
            classification: string;
            match_type: string | null;
            matched_entry: string | null;
            match_response: {} | null;
            pdq_hash_hex: string;
            pdq_hash_base64: string;
            frame: number;
            frames: {
                total: number;
                checked: number;
            } | null;
            all_frame_hashes_base64: string[];
        };
        "6_when_and_where": {
            posted_or_uploaded_at: string;
            detected_at: string;
            where: string;
            url: string | null;
            discord_server_id: string;
            discord_server_name: string | null;
            discord_channel_id: string | null;
            discord_message_id: string | null;
            discord_attachment_id: string | null;
        };
        "7_relevant_data_two_weeks": {
            at_match: {} | null;
            at_match_error: string | null;
            added_since: Record<string, unknown>;
        };
        "8_previous_reports": {
            relates_to_previous_report: boolean;
            reports: PreviousReport[];
        };
        not_available: string[];
        quarantine_id: string;
        report: {
            reference: string;
            reported_at: string;
            recorded_by: string;
            recorded_at: string;
            /** Set when it went through the API: the NCA's own ids. */
            via_api?: {
                referral_id: string;
                report_id?: number;
            };
            /** Sent without the file (e.g. the NCA's service refused its bytes), and why. */
            file_not_sent?: string;
            /**
             * The NCA said the report's media did not all upload (their email "Some
             * media files have not uploaded"). Cleared by a supplementary report.
             */
            media_missing?: {
                note: string;
                set_by: string;
                set_at: string;
            };
        } | null;
    }>;
    /**
     * Everything the report's fields are made from that is not in the record:
     * earlier reports about the same user or image, and the file's EXIF.
     */
    private fieldsFor;
    /**
     * Reports already sent that this one relates to (Schedule 1: "whether it
     * relates to a previous report"): the same Discord user, the same image
     * by its PDQ hash, or the same server within two weeks either side (one
     * incident in one server, reported per file). Read from the kept references, which outlive their
     * items. References made before `user_id` was kept match by image only,
     * unless their item is still here to say who it was about.
     */
    previousReports(item: QuarantineRecord): Promise<PreviousReport[]>;
    /**
     * Stop (reason) or allow (null) automatic reporting of one item. A report
     * an admin submits by hand is not affected.
     */
    setAutoReport(id: string, pausedReason: string | null, actor: string): Promise<QuarantineRecord>;
    /**
     * Why an item is not reported automatically, or null when it should be.
     * `others` are the other items, to find one that already covers the same
     * file: the same attachment matched when stored and again before re-upload,
     * or copied by more than one bot (a server with both main and Pro). The
     * earliest is reported; ties go to the lower id.
     */
    autoReportBlocker(record: QuarantineSummary, others?: QuarantineSummary[]): string | null;
    /**
     * Report one item to the NCA through the API: the fields, a JSON document
     * with everything else held, and the file itself, sent from here. The
     * reference is then recorded as for any report. Throws; the failure is kept
     * on the item, and only one that certainly was not processed
     * (`ncaFailureKind` "retry") is tried again automatically.
     */
    /**
     * The quarantined file as it will be sent: read, checked against the
     * checksum recorded when it was kept, and named and typed from its own
     * bytes. Throws `NcaLocalError` when it is missing or does not match: the
     * report is then not sent, rather than sent without its file.
     */
    private mediaFor;
    /** Every record, without logging a list (internal use). */
    private allRecords;
    /**
     * The same uploader's other matches to attach to a `csam` report as other
     * relevant information (reg. 6(4)(d)): unreported `harmful-abusive-material`
     * matches with a stored file, not already sent with a report. Only for a
     * match found by the image check (not a report recorded by hand).
     */
    relatedMatches(record: QuarantineSummary, all: QuarantineSummary[]): QuarantineSummary[];
    /** The files for one report, the payload adjusted to list them, and lines to add. */
    private build;
    /** Mark matches as sent with a report: kept a year from it, never cleared. */
    private markIncluded;
    private noteFailure;
    /**
     * Report one item to the NCA. `withoutFile`: send an initial report without
     * the file, giving the reason (SI 2026/268 reg. 6(5)); the file follows in
     * a supplementary report.
     */
    submitToNca(id: string, actor: string, config: NcaConfig, app?: AppReportData, { withoutFile }?: {
        withoutFile?: string;
    }): Promise<{
        record: QuarantineRecord;
        result: NcaResult;
    }>;
    /**
     * Record that the NCA said the media of an item's report did not all upload
     * (their email names the reference). The item then shows a supplementary
     * report is needed.
     */
    markMediaMissing(id: string, note: string, actor: string): Promise<QuarantineRecord>;
    /**
     * A supplementary report (SI 2026/268 reg. 6(5)): the same report again
     * with the file, naming the earlier reference, for a report sent without
     * the file or whose media the NCA did not receive. Keeps the item a year
     * from this report, and the new reference with the old.
     */
    submitSupplementary(id: string, actor: string, config: NcaConfig, app?: AppReportData, { chatDocument: chatOnly }?: {
        chatDocument?: boolean;
    }): Promise<{
        record: QuarantineRecord;
        result: NcaResult;
    }>;
    /**
     * Record the NCA's reference for a submitted report. The item is then kept
     * at least a year from the report date, and the reference five years.
     */
    recordReport(id: string, { reference, reportedAt, submitted, viaApi, }: {
        reference: string;
        reportedAt: string;
        /** The report as submitted; the fields as they stand when not given. */
        submitted?: unknown;
        viaApi?: {
            referral_id: string;
            report_id?: number;
        };
    }, actor: string): Promise<QuarantineRecord>;
    /** Report references still kept, including those whose item has gone. */
    references(actor: string): Promise<QuarantineReference[]>;
    /** Write (or replace) one case in the report register. */
    putRegister(entry: RegisterEntry, actor: string): Promise<void>;
    /** Every case in the report register, oldest first. */
    register(actor: string): Promise<RegisterEntry[]>;
    /**
     * Delete what has passed its time: items a year after detection (or after
     * the report, if later), references five years after the report, and access
     * log entries five years old. Run daily by the bots. Each deletion is logged.
     */
    sweep(actor?: string): Promise<{
        items: number;
        references: number;
        accessEntries: number;
    }>;
}
/** What an app adds to the report that the quarantine does not hold. */
export interface AppReportData {
    /**
     * The user's billing records with the app (Schedule 1, item 4: name,
     * address and date of birth from billing details, email, phone), one per
     * customer record. `[]` when the app looked and found none; left out when
     * it did not look.
     */
    billing?: BillingRecord[];
    /** Set when the app could not look, e.g. the payment provider was down. */
    billingError?: string;
}
export interface BillingRecord {
    /** Where it is held, e.g. "Stripe customer cus_123". */
    source: string;
    name?: string | null;
    email?: string | null;
    phone?: string | null;
    address?: Record<string, string | null> | null;
    /** Names and addresses on payment methods, which may differ. */
    payment_methods?: {
        type: string;
        name?: string | null;
        email?: string | null;
        phone?: string | null;
        address?: Record<string, string | null> | null;
    }[];
    created_at?: string;
}
export interface PreviousReport {
    reference: string;
    reported_at: string;
    quarantine_id: string;
    relates_by: string;
}
export type ExifResult = {
    tags: Record<string, unknown> | null;
    raw_base64: string | null;
} | {
    error: string;
};
/**
 * The file's EXIF (Schedule 1: "linked exif data"): readable tags, GPS
 * included, and the raw block so nothing is lost in reading it. Discord
 * strips some of it from uploads, so `tags: null` is a normal answer.
 */
export declare function exifOf(content: Buffer): Promise<ExifResult>;
/**
 * The report's fields from an item: Schedule 1, "where available", in the
 * order the report is made (reporter, urgency, the user, the content and how
 * it was found, where and when, the relevant data). What Quark does not hold
 * is named under `not_available` rather than left out silently.
 *
 * `extra` is what is not in the record: earlier reports and the EXIF (read
 * by the store), and billing records (from the app, which holds them).
 */
export declare function reportFieldsOf(item: QuarantineRecord | QuarantineItem, extra?: AppReportData & {
    previousReports?: PreviousReport[];
    exif?: ExifResult;
}): {
    "1_reporting_service": {
        name: string;
        description: string;
    };
    "2_priority": {
        level: "immediate_risk" | "serious_harm" | "other";
        meaning: string;
    } | {
        level: null;
        meaning: string;
    };
    "3_user": {
        discord_user_id: string | null;
        username: string | null;
        display_name: string | null;
        profile_url: string | null;
        account_created_at: string | null;
        ip_address: string | null;
        ip_address_time: string | null;
        user_agent: string | null;
        billing: BillingRecord[] | null;
    };
    "4_content": {
        description: string;
        file_type: string | null;
        file_name: string | null;
        size_bytes: number;
        sha256: string;
        exif: ExifResult | null;
        held: string;
    };
    "5_how_detected": {
        method: string;
        provider: string;
        classification: string;
        match_type: string | null;
        matched_entry: string | null;
        match_response: {} | null;
        pdq_hash_hex: string;
        pdq_hash_base64: string;
        frame: number;
        frames: {
            total: number;
            checked: number;
        } | null;
        all_frame_hashes_base64: string[];
    };
    "6_when_and_where": {
        posted_or_uploaded_at: string;
        detected_at: string;
        where: string;
        url: string | null;
        discord_server_id: string;
        discord_server_name: string | null;
        discord_channel_id: string | null;
        discord_message_id: string | null;
        discord_attachment_id: string | null;
    };
    "7_relevant_data_two_weeks": {
        at_match: {} | null;
        at_match_error: string | null;
        added_since: Record<string, unknown>;
    };
    "8_previous_reports": {
        relates_to_previous_report: boolean;
        reports: PreviousReport[];
    };
    not_available: string[];
    quarantine_id: string;
    report: {
        reference: string;
        reported_at: string;
        recorded_by: string;
        recorded_at: string;
        /** Set when it went through the API: the NCA's own ids. */
        via_api?: {
            referral_id: string;
            report_id?: number;
        };
        /** Sent without the file (e.g. the NCA's service refused its bytes), and why. */
        file_not_sent?: string;
        /**
         * The NCA said the report's media did not all upload (their email "Some
         * media files have not uploaded"). Cleared by a supplementary report.
         */
        media_missing?: {
            note: string;
            set_by: string;
            set_at: string;
        };
    } | null;
};
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
export declare function quarantineFromEnv(env?: NodeJS.ProcessEnv): Quarantine | undefined;
export * from "./nca.js";
