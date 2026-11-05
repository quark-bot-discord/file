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
  action:
    | "write"
    | "list"
    | "read"
    | "export_fields"
    | "export_content"
    | "record_report"
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

  /** One item's record, with its relevant data. Not the file. */
  async get(id: string, actor: string): Promise<QuarantineRecord> {
    const record = await this.readRecord(id);
    await this.logAccess({ actor, action: "read", id });
    return record;
  }

  /**
   * The fields a report needs (Schedule 1, "where available"), as one
   * object. Logged as an export.
   */
  async reportFields(id: string, actor: string) {
    const record = await this.readRecord(id);
    await this.logAccess({ actor, action: "export_fields", id });
    return reportFieldsOf(record);
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
    { reference, reportedAt }: { reference: string; reportedAt: string },
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
    await this.putSealed(`references/${id}`, Buffer.from(JSON.stringify(kept)));
    await this.putSealed(
      `items/${id}/record`,
      Buffer.from(JSON.stringify(record)),
    );
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
      if (Date.parse(record.expires_at) > now.getTime()) continue;
      await this.remove(`items/${id}/content`);
      await this.remove(`items/${id}/record`);
      await this.logAccess({ actor, action: "expire", id });
      items++;
    }
    for (const name of await this.listNames("references/")) {
      const plain = await this.getSealed(name);
      if (!plain) continue;
      const kept = JSON.parse(plain.toString("utf8")) as QuarantineReference;
      if (Date.parse(kept.expires_at) > now.getTime()) continue;
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

/**
 * The report's fields from a record: Schedule 1, "where available". What
 * Quark does not hold is named under `not_available` rather than left out
 * silently.
 */
export function reportFieldsOf(record: QuarantineRecord) {
  const s = record.subject;
  const d = record.detection;
  const notAvailable: string[] = [];
  if (!s.ip)
    notAvailable.push(
      record.source === "dashboard"
        ? "IP address: not received with this upload"
        : "IP address: Discord does not give bots the IP address of the person who posted",
    );
  notAvailable.push(
    "Email address and phone number: Quark does not receive them from Discord",
  );
  if (!s.user_id) notAvailable.push("Discord account: not known for this file");
  return {
    prepared_at: new Date().toISOString(),
    quarantine_id: record.id,
    reporting_service: {
      name: "Quark",
      description:
        "Discord bot that logs server activity, and its dashboard at quark.bot",
    },
    content: {
      description:
        "Image file matched against known material by perceptual hash. Not viewed.",
      file_type: record.content.type ?? null,
      file_name: record.content.name ?? null,
      size_bytes: record.content.bytes,
      sha256: record.content.sha256,
      held: "Kept encrypted in Quark's restricted store; exported separately on request.",
    },
    detection: {
      method:
        "PDQ perceptual hash computed by Quark and matched by Project Arachnid Shield (Canadian Centre for Child Protection). Only the hash was sent.",
      provider: d.provider,
      classification: d.category,
      match_type: d.match_type,
      matched_entry: d.reference ?? null,
      pdq_hash_base64: d.pdq,
      pdq_hash_hex: Buffer.from(d.pdq, "base64").toString("hex"),
      frame: d.frame ?? 0,
      frames: d.frames ?? null,
      all_frame_hashes_base64: d.hashes ?? [d.pdq],
      detected_at: record.detected_at,
      where: d.stage === "upload"
        ? `Upload to the dashboard${s.route ? ` (${s.route})` : ""}`
        : d.stage === "store"
          ? "Attachment posted in a Discord server, checked when Quark stored it for its logs"
          : "Attachment stored by Quark, checked before Quark re-posted it in a log",
    },
    upload: {
      time: d.time,
      ip_address: s.ip ?? null,
      user_agent: s.user_agent ?? null,
    },
    user: {
      discord_user_id: s.user_id ?? null,
      username: s.username ?? null,
      display_name: s.display_name ?? null,
      account_created_at: snowflakeTime(s.user_id) ?? null,
    },
    location: {
      discord_server_id: s.guild_id ?? d.guild_id ?? null,
      discord_channel_id: s.channel_id ?? d.channel_id ?? null,
      discord_message_id: s.message_id ?? null,
      discord_attachment_id: s.attachment_id ?? d.attachment_id ?? null,
    },
    relevant_data_two_weeks: record.relevant_data ?? null,
    relevant_data_error: record.relevant_data_error ?? null,
    report: record.report ?? null,
    not_available: notAvailable,
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
