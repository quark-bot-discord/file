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
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import type { Detection } from "../scan/scanner.js";

const DAY_MS = 24 * 60 * 60 * 1000;
/** reg 8: content, report, basis and relevant data. */
export const RETENTION_DAYS = 365;
/** reg 8: the report reference. */
export const REFERENCE_RETENTION_DAYS = 5 * 365;

const MAGIC = Buffer.from("QZ1");

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
export const PRIORITIES = ["immediate_risk", "serious_harm", "other"] as const;
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
  };
  subject: QuarantineSubject;
  /** The user's relevant data from the two weeks before, as the app held it. */
  relevant_data?: unknown;
  relevant_data_error?: string;
  /** When `sweep` deletes the item, unless it is on hold. */
  expires_at: string;
  priority?: { level: Priority; set_by: string; set_at: string };
  /** Kept past its time: a law-enforcement request. Cleared to let it expire. */
  hold?: { reason: string; set_by: string; set_at: string };
  report?: {
    reference: string;
    reported_at: string;
    recorded_by: string;
    recorded_at: string;
  };
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
  expires_at: string;
  hold?: QuarantineRecord["hold"];
}

export interface AccessEntry {
  time: string;
  /** `admin:<discord id>`, or `system:<what>` for the apps themselves. */
  actor: string;
  action:
    | "write"
    | "list"
    | "read"
    | "export_fields"
    | "export_content"
    | "record_report"
    | "set_priority"
    | "set_hold"
    | "add_relevant_data"
    | "expire"
    | "expire_reference";
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

export class QuarantineNotFound extends Error {}

/** Seal bytes under the key, bound to the object name. */
export function seal(key: Buffer, name: string, plain: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(name));
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), body]);
}

/** Open what `seal` made. Throws if the key, the name or a byte is wrong. */
export function unseal(key: Buffer, name: string, sealed: Buffer): Buffer {
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
export function parseKey(raw: string): Buffer {
  const text = raw.trim();
  const key = /^[0-9a-f]{64}$/i.test(text)
    ? Buffer.from(text, "hex")
    : Buffer.from(text, "base64");
  if (key.length !== 32)
    throw new Error(
      "QUARANTINE_KEY must be 32 bytes, as 64 hex characters or base64",
    );
  return key;
}

const addDays = (iso: string, days: number) =>
  new Date(Date.parse(iso) + days * DAY_MS).toISOString();
const later = (a: string, b: string) => (Date.parse(a) >= Date.parse(b) ? a : b);

async function bodyBytes(body: any): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof body.transformToByteArray === "function")
    return Buffer.from(await body.transformToByteArray());
  const chunks: Buffer[] = [];
  for await (const chunk of body) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

const notFound = (error: any) =>
  error?.name === "NoSuchKey" ||
  error?.name === "NotFound" ||
  error?.$metadata?.httpStatusCode === 404;

export class Quarantine {
  private client: ObjectClient;
  private bucket: string;
  private key: Buffer;
  private now: () => Date;

  constructor({
    client,
    bucket,
    key,
    now = () => new Date(),
  }: {
    client: ObjectClient;
    bucket: string;
    /** 32 bytes. */
    key: Buffer;
    now?: () => Date;
  }) {
    if (key.length !== 32) throw new Error("The quarantine key must be 32 bytes");
    this.client = client;
    this.bucket = bucket;
    this.key = key;
    this.now = now;
  }

  /* ---------------- objects ---------------- */

  private async putSealed(name: string, plain: Buffer) {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: name,
        Body: seal(this.key, name, plain),
        ContentType: "application/octet-stream",
      }),
    );
  }

  private async getSealed(name: string): Promise<Buffer | null> {
    try {
      const res = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: name }),
      );
      return unseal(this.key, name, await bodyBytes(res.Body));
    } catch (error) {
      if (notFound(error)) return null;
      throw error;
    }
  }

  private async remove(name: string) {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: name }),
    );
  }

  private async listNames(prefix: string): Promise<string[]> {
    const names: string[] = [];
    let token: string | undefined;
    do {
      const res = await this.client.send(
        new ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: prefix,
          ContinuationToken: token,
        }),
      );
      for (const item of res.Contents ?? []) if (item.Key) names.push(item.Key);
      token = res.IsTruncated ? res.NextContinuationToken : undefined;
    } while (token);
    return names;
  }

  /** Append to the access log. A failure here fails the access. */
  async logAccess(entry: Omit<AccessEntry, "time">) {
    const time = this.now().toISOString();
    const name = `access/${time.slice(0, 4)}/${time.slice(5, 7)}/${time}-${randomBytes(4).toString("hex")}.json`;
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: name,
        Body: JSON.stringify({ time, ...entry } satisfies AccessEntry),
        ContentType: "application/json",
      }),
    );
  }

  /** The access log, newest first, up to `limit` entries. */
  async accessLog(actor: string, limit = 200): Promise<AccessEntry[]> {
    const names = (await this.listNames("access/")).sort().reverse();
    const entries: AccessEntry[] = [];
    for (const name of names.slice(0, limit)) {
      const res = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: name }),
      );
      entries.push(JSON.parse((await bodyBytes(res.Body)).toString("utf8")));
    }
    await this.logAccess({ actor, action: "read", detail: "access log" });
    return entries;
  }

  /* ---------------- items ---------------- */

  /** Keep a matched file and its data. Resolves with the item's id. */
  async put(input: PutInput): Promise<string> {
    const at = this.now();
    const id = `${at.getTime().toString(36)}-${randomBytes(6).toString("hex")}`;
    const detectedAt = at.toISOString();
    const record: QuarantineRecord = {
      id,
      version: 1,
      detected_at: detectedAt,
      source: input.detection.source ?? "unknown",
      detection: input.detection,
      content: {
        stored: true,
        bytes: input.content.length,
        sha256: createHash("sha256").update(input.content).digest("hex"),
        type: input.contentType,
        name: input.fileName,
      },
      subject: input.subject,
      relevant_data: input.relevantData,
      relevant_data_error: input.relevantDataError,
      expires_at: addDays(detectedAt, RETENTION_DAYS),
    };
    // Content first: a record never points at content that was not written.
    await this.putSealed(`items/${id}/content`, input.content);
    await this.putSealed(
      `items/${id}/record`,
      Buffer.from(JSON.stringify(record)),
    );
    await this.logAccess({
      actor: `system:${record.source}`,
      action: "write",
      id,
    });
    return id;
  }

  private async readRecord(id: string): Promise<QuarantineRecord> {
    if (!/^[a-z0-9]+-[0-9a-f]{12}$/.test(id))
      throw new QuarantineNotFound(id);
    const plain = await this.getSealed(`items/${id}/record`);
    if (!plain) throw new QuarantineNotFound(id);
    return JSON.parse(plain.toString("utf8")) as QuarantineRecord;
  }

  private async recordIds(): Promise<string[]> {
    return (await this.listNames("items/"))
      .filter((name) => name.endsWith("/record"))
      .map((name) => name.slice("items/".length, -"/record".length));
  }

  /** Every item, newest first, without the relevant data or the file. */
  async list(actor: string): Promise<QuarantineSummary[]> {
    const ids = (await this.recordIds()).sort().reverse();
    const records: QuarantineSummary[] = [];
    for (const id of ids) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { relevant_data, ...summary } = await this.readRecord(id);
        records.push(summary);
      } catch (error) {
        if (!(error instanceof QuarantineNotFound)) throw error;
      }
    }
    await this.logAccess({ actor, action: "list", detail: `${records.length} items` });
    return records;
  }

  /** One item's record, with its relevant data and the report as submitted. Not the file. */
  async get(id: string, actor: string): Promise<QuarantineItem> {
    const item = await this.readItem(id);
    await this.logAccess({ actor, action: "read", id });
    return item;
  }

  private async readItem(id: string): Promise<QuarantineItem> {
    const record = await this.readRecord(id);
    const parts: Record<string, unknown> = {};
    for (const name of await this.listNames(`items/${id}/relevant/`)) {
      const plain = await this.getSealed(name);
      if (plain)
        parts[name.slice(`items/${id}/relevant/`.length)] = JSON.parse(
          plain.toString("utf8"),
        );
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
  async addRelevantData(
    id: string,
    part: string,
    data: unknown,
    actor: string,
  ): Promise<void> {
    if (!/^[a-z0-9-]{1,32}$/.test(part)) throw new Error("Bad part name");
    await this.readRecord(id);
    await this.putSealed(
      `items/${id}/relevant/${part}`,
      Buffer.from(JSON.stringify(data)),
    );
    await this.logAccess({ actor, action: "add_relevant_data", id, detail: part });
  }

  /** How urgent the report is. */
  async setPriority(
    id: string,
    level: Priority,
    actor: string,
  ): Promise<QuarantineRecord> {
    if (!PRIORITIES.includes(level)) throw new Error("Unknown priority");
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
  async setHold(
    id: string,
    reason: string | null,
    actor: string,
  ): Promise<QuarantineRecord> {
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
      const kept = JSON.parse(plain.toString("utf8")) as QuarantineReference;
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

  private async writeRecord(record: QuarantineRecord) {
    await this.putSealed(
      `items/${record.id}/record`,
      Buffer.from(JSON.stringify(record)),
    );
  }

  /**
   * The fields a report needs (Schedule 1, "where available"), as one
   * object. Logged as an export.
   */
  async reportFields(id: string, actor: string) {
    const item = await this.readItem(id);
    await this.logAccess({ actor, action: "export_fields", id });
    return reportFieldsOf(item);
  }

  /**
   * The file, sealed again under a new one-off key, for handing to the NCA.
   * The stored copy and its key never leave; the one-off key is returned once
   * and is not kept anywhere.
   */
  async exportContent(
    id: string,
    actor: string,
  ): Promise<{ sealed: Buffer; key: string; sha256: string; name: string }> {
    const record = await this.readRecord(id);
    const content = await this.getSealed(`items/${id}/content`);
    if (!content) throw new QuarantineNotFound(id);
    const oneOff = randomBytes(32);
    const name = `quarantine-${id}.bin`;
    await this.logAccess({ actor, action: "export_content", id });
    return {
      sealed: seal(oneOff, name, content),
      key: oneOff.toString("base64"),
      sha256: record.content.sha256,
      name,
    };
  }

  /**
   * Record the NCA's reference for a submitted report. The item is then kept
   * at least a year from the report date, and the reference five years.
   */
  async recordReport(
    id: string,
    {
      reference,
      reportedAt,
      submitted,
    }: {
      reference: string;
      reportedAt: string;
      /** The report as submitted; the fields as they stand when not given. */
      submitted?: unknown;
    },
    actor: string,
  ): Promise<QuarantineRecord> {
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
    };
    record.expires_at = later(
      record.expires_at,
      addDays(reportedIso, RETENTION_DAYS),
    );
    const kept: QuarantineReference = {
      id,
      reference: cleanReference,
      reported_at: reportedIso,
      detected_at: record.detected_at,
      category: record.detection.category,
      pdq: record.detection.pdq,
      expires_at: addDays(reportedIso, REFERENCE_RETENTION_DAYS),
    };
    kept.hold = record.hold;
    const asSubmitted =
      submitted ?? reportFieldsOf(await this.readItem(id));
    await this.putSealed(
      `items/${id}/submitted`,
      Buffer.from(
        JSON.stringify({
          reference: cleanReference,
          reported_at: reportedIso,
          report: asSubmitted,
        }),
      ),
    );
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
  async references(actor: string): Promise<QuarantineReference[]> {
    const out: QuarantineReference[] = [];
    for (const name of await this.listNames("references/")) {
      const plain = await this.getSealed(name);
      if (plain) out.push(JSON.parse(plain.toString("utf8")));
    }
    await this.logAccess({ actor, action: "read", detail: "references" });
    return out;
  }

  /**
   * Delete what has passed its time: items a year after detection (or after
   * the report, if later), references five years after the report, and access
   * log entries five years old. Run daily by the bots. Each deletion is logged.
   */
  async sweep(
    actor = "system:sweep",
  ): Promise<{ items: number; references: number; accessEntries: number }> {
    const now = this.now();
    let items = 0;
    let references = 0;
    let accessEntries = 0;
    for (const id of await this.recordIds()) {
      let record: QuarantineRecord;
      try {
        record = await this.readRecord(id);
      } catch (error) {
        if (error instanceof QuarantineNotFound) continue;
        throw error;
      }
      if (record.hold || Date.parse(record.expires_at) > now.getTime())
        continue;
      // The record last, so an interrupted sweep is finished next time.
      for (const name of await this.listNames(`items/${id}/`))
        if (name !== `items/${id}/record`) await this.remove(name);
      await this.remove(`items/${id}/record`);
      await this.logAccess({ actor, action: "expire", id });
      items++;
    }
    for (const name of await this.listNames("references/")) {
      const plain = await this.getSealed(name);
      if (!plain) continue;
      const kept = JSON.parse(plain.toString("utf8")) as QuarantineReference;
      if (kept.hold || Date.parse(kept.expires_at) > now.getTime()) continue;
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
function snowflakeTime(id?: string): string | undefined {
  if (!id || !/^\d{17,20}$/.test(id)) return undefined;
  return new Date(Number((BigInt(id) >> 22n) + 1420070400000n)).toISOString();
}

const PRIORITY_TEXT: Record<Priority, string> = {
  immediate_risk:
    "A child is at immediate risk: call 999 first, then report",
  serious_harm:
    "Risk of serious harm: report as soon as reasonably practicable",
  other: "Report without undue delay",
};

/**
 * The report's fields from an item: Schedule 1, "where available", in the
 * order the report is made (reporter, urgency, the user, the content and how
 * it was found, where and when, the relevant data). What Quark does not hold
 * is named under `not_available` rather than left out silently.
 */
export function reportFieldsOf(item: QuarantineRecord | QuarantineItem) {
  const s = item.subject;
  const d = item.detection;
  const notAvailable: string[] = [];
  if (!s.ip)
    notAvailable.push(
      item.source === "dashboard"
        ? "IP address: not received with this upload"
        : "IP address: not available. Discord does not give bots the IP address of the person who posted",
    );
  notAvailable.push(
    "Email address and phone number: Quark does not receive them from Discord",
  );
  if (!s.user_id) notAvailable.push("Discord account: not known for this file");
  if (!s.guild_name) notAvailable.push("Server name: not known at the time");
  const parts =
    "relevant_data_parts" in item ? item.relevant_data_parts : {};
  return {
    "1_reporting_service": {
      name: "Quark",
      description:
        "Discord bot that logs server activity, and its dashboard at quark.bot",
    },
    "2_priority": item.priority
      ? { level: item.priority.level, meaning: PRIORITY_TEXT[item.priority.level] }
      : { level: null, meaning: "Not chosen yet" },
    "3_user": {
      discord_user_id: s.user_id ?? null,
      username: s.username ?? null,
      display_name: s.display_name ?? null,
      account_created_at: snowflakeTime(s.user_id) ?? null,
      ip_address: s.ip ?? null,
      ip_address_time: s.ip ? d.time : null,
      user_agent: s.user_agent ?? null,
    },
    "4_content": {
      description:
        "Image file matched against known material by perceptual hash. Not viewed by Quark.",
      file_type: item.content.type ?? null,
      file_name: item.content.name ?? null,
      size_bytes: item.content.bytes,
      sha256: item.content.sha256,
      held: "Kept encrypted in Quark's restricted store; the file is handed over separately.",
    },
    "5_how_detected": {
      method:
        "PDQ perceptual hash computed by Quark and matched by Project Arachnid Shield (Canadian Centre for Child Protection). Only the hash was sent.",
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
      where:
        d.stage === "upload"
          ? `Upload to the quark.bot dashboard${s.route ? ` (${s.route})` : ""}`
          : d.stage === "store"
            ? "Attachment posted in a Discord server, checked when Quark stored it for its logs"
            : "Attachment stored by Quark, checked before Quark re-posted it in a log",
      discord_server_id: s.guild_id ?? d.guild_id ?? null,
      discord_server_name: s.guild_name ?? null,
      discord_channel_id: s.channel_id ?? d.channel_id ?? null,
      discord_message_id: s.message_id ?? null,
      discord_attachment_id: s.attachment_id ?? d.attachment_id ?? null,
    },
    "7_relevant_data_two_weeks": {
      at_match: item.relevant_data ?? null,
      at_match_error: item.relevant_data_error ?? null,
      added_since: parts,
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
export function quarantineFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Quarantine | undefined {
  const bucket = env.QUARANTINE_BUCKET;
  const rawKey = env.QUARANTINE_KEY;
  const endpoint = env.QUARANTINE_S3_URL || env.S3_URI;
  const accessKeyId = env.QUARANTINE_S3_ACCESS_KEY_ID || env.S3_ACCESS_KEY_ID;
  const secretAccessKey =
    env.QUARANTINE_S3_SECRET_ACCESS_KEY || env.S3_ACCESS_KEY_SECRET;
  if (!bucket || !rawKey || !endpoint || !accessKeyId || !secretAccessKey)
    return undefined;
  let key: Buffer;
  try {
    key = parseKey(rawKey);
  } catch (error) {
    console.error(`[FILE SCAN] QUARANTINE OFF: ${(error as Error).message}`);
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

/** Open a file exported by `exportContent`, given its one-off key. */
export function openExport(sealed: Buffer, key: string, name: string): Buffer {
  return unseal(Buffer.from(key, "base64"), name, sealed);
}
