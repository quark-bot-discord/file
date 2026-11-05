import type { Detection } from "../scan/scanner.js";
/** reg 8: content, report, basis and relevant data. */
export declare const RETENTION_DAYS = 365;
/** reg 8: the report reference. */
export declare const REFERENCE_RETENTION_DAYS: number;
/** Who sent it and from where, as far as the app that found it knows. */
export interface QuarantineSubject {
    /** Discord user id. */
    user_id?: string;
    username?: string;
    display_name?: string;
    guild_id?: string;
    channel_id?: string;
    message_id?: string;
    attachment_id?: string;
    /** Dashboard uploads only: the client IP from the site's trusted header. */
    ip?: string;
    user_agent?: string;
    /** Dashboard uploads only: the route it was sent to. */
    route?: string;
}
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
    };
    subject: QuarantineSubject;
    /** The user's relevant data from the two weeks before, as the app held it. */
    relevant_data?: unknown;
    relevant_data_error?: string;
    /** When `sweep` deletes the item. */
    expires_at: string;
    report?: {
        reference: string;
        reported_at: string;
        recorded_by: string;
        recorded_at: string;
    };
}
/** What is listed on the admin page: everything but the relevant data. */
export type QuarantineSummary = Omit<QuarantineRecord, "relevant_data">;
export interface QuarantineReference {
    id: string;
    reference: string;
    reported_at: string;
    detected_at: string;
    category: string;
    pdq: string;
    expires_at: string;
}
export interface AccessEntry {
    time: string;
    /** `admin:<discord id>`, or `system:<what>` for the apps themselves. */
    actor: string;
    action: "write" | "list" | "read" | "export_fields" | "export_content" | "record_report" | "expire" | "expire_reference";
    id?: string;
    detail?: string;
}
export interface PutInput {
    detection: Detection;
    content: Buffer;
    contentType?: string;
    fileName?: string;
    subject: QuarantineSubject;
    relevantData?: unknown;
    relevantDataError?: string;
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
    /** Keep a matched file and its data. Resolves with the item's id. */
    put(input: PutInput): Promise<string>;
    private readRecord;
    private recordIds;
    /** Every item, newest first, without the relevant data or the file. */
    list(actor: string): Promise<QuarantineSummary[]>;
    /** One item's record, with its relevant data. Not the file. */
    get(id: string, actor: string): Promise<QuarantineRecord>;
    /**
     * The fields a report needs (Schedule 1, "where available"), as one
     * object. Logged as an export.
     */
    reportFields(id: string, actor: string): Promise<{
        prepared_at: string;
        quarantine_id: string;
        reporting_service: {
            name: string;
            description: string;
        };
        content: {
            description: string;
            file_type: string | null;
            file_name: string | null;
            size_bytes: number;
            sha256: string;
            held: string;
        };
        detection: {
            method: string;
            provider: string;
            classification: string;
            match_type: string | null;
            matched_entry: string | null;
            pdq_hash_base64: string;
            pdq_hash_hex: string;
            frame: number;
            frames: {
                total: number;
                checked: number;
            } | null;
            all_frame_hashes_base64: string[];
            detected_at: string;
            where: string;
        };
        upload: {
            time: string;
            ip_address: string | null;
            user_agent: string | null;
        };
        user: {
            discord_user_id: string | null;
            username: string | null;
            display_name: string | null;
            account_created_at: string | null;
        };
        location: {
            discord_server_id: string;
            discord_channel_id: string | null;
            discord_message_id: string | null;
            discord_attachment_id: string | null;
        };
        relevant_data_two_weeks: {} | null;
        relevant_data_error: string | null;
        report: {
            reference: string;
            reported_at: string;
            recorded_by: string;
            recorded_at: string;
        } | null;
        not_available: string[];
    }>;
    /**
     * The file, sealed again under a new one-off key, for handing to the NCA.
     * The stored copy and its key never leave; the one-off key is returned once
     * and is not kept anywhere.
     */
    exportContent(id: string, actor: string): Promise<{
        sealed: Buffer;
        key: string;
        sha256: string;
        name: string;
    }>;
    /**
     * Record the NCA's reference for a submitted report. The item is then kept
     * at least a year from the report date, and the reference five years.
     */
    recordReport(id: string, { reference, reportedAt }: {
        reference: string;
        reportedAt: string;
    }, actor: string): Promise<QuarantineRecord>;
    /** Report references still kept, including those whose item has gone. */
    references(actor: string): Promise<QuarantineReference[]>;
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
/**
 * The report's fields from a record: Schedule 1, "where available". What
 * Quark does not hold is named under `not_available` rather than left out
 * silently.
 */
export declare function reportFieldsOf(record: QuarantineRecord): {
    prepared_at: string;
    quarantine_id: string;
    reporting_service: {
        name: string;
        description: string;
    };
    content: {
        description: string;
        file_type: string | null;
        file_name: string | null;
        size_bytes: number;
        sha256: string;
        held: string;
    };
    detection: {
        method: string;
        provider: string;
        classification: string;
        match_type: string | null;
        matched_entry: string | null;
        pdq_hash_base64: string;
        pdq_hash_hex: string;
        frame: number;
        frames: {
            total: number;
            checked: number;
        } | null;
        all_frame_hashes_base64: string[];
        detected_at: string;
        where: string;
    };
    upload: {
        time: string;
        ip_address: string | null;
        user_agent: string | null;
    };
    user: {
        discord_user_id: string | null;
        username: string | null;
        display_name: string | null;
        account_created_at: string | null;
    };
    location: {
        discord_server_id: string;
        discord_channel_id: string | null;
        discord_message_id: string | null;
        discord_attachment_id: string | null;
    };
    relevant_data_two_weeks: {} | null;
    relevant_data_error: string | null;
    report: {
        reference: string;
        reported_at: string;
        recorded_by: string;
        recorded_at: string;
    } | null;
    not_available: string[];
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
/** Open a file exported by `exportContent`, given its one-off key. */
export declare function openExport(sealed: Buffer, key: string, name: string): Buffer;
