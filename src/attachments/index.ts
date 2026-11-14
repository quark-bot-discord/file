/**
 * The stored copies of Discord attachments, for an admin acting on a report
 * or an erasure request from the website (`/admin/takedowns`), so nothing
 * has to be run by hand in a bot's pod.
 *
 * - `find`: which of the names a copy can have exist (HEAD only).
 * - `read`: the original bytes, decrypted, for keeping in the quarantine
 *   before a delete. Never shown to anyone.
 * - `delete`: removes every stored name.
 *
 * Each bot has its own bucket, so a store is made per bucket. The object name
 * depends on whether the server had Pro when the file was saved and on
 * whether it was stored with extended expiry, so all four are tried.
 *
 * The key derivation needs the attachment's size in bytes. Copies stored
 * since this module exist carry it (`sz`); for older ones the caller passes
 * the sizes it knows (the log archive, or the admin), and each is tried until
 * one decrypts and decompresses.
 */
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { Readable } from "node:stream";
import FileStorage from "../index.js";
import { fetchFile as decryptStream } from "../core/fetchFile.js";
import type { ObjectClient } from "../quarantine/index.js";

export interface AttachmentRef {
  guildId: string;
  channelId: string;
  attachmentId: string;
}

export interface FoundCopy {
  name: string;
  /** The original size, when the copy recorded it. */
  size: number | null;
  keyVersion: 1 | 2;
  /** A marker left when the image check matched at download: no file. */
  withheld: string | null;
}

/** `.../attachments/<channel_id>/<attachment_id>/<filename>` */
export function attachmentFromUrl(url: string): { channelId: string; attachmentId: string } | null {
  const match = /\/attachments\/(\d{15,21})\/(\d{15,21})\//.exec(url);
  return match ? { channelId: match[1], attachmentId: match[2] } : null;
}

/** Every name one stored copy can have. */
export function storedNames(ref: AttachmentRef, keys: string[] = []): string[] {
  const name = FileStorage.prototype.getFileName as (
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key: string | null,
    extendedExpiration: boolean,
  ) => string;
  const names: string[] = [];
  for (const key of [null, ...keys])
    for (const extended of [false, true])
      for (const premium of [false, true])
        names.push(name(ref.attachmentId, ref.channelId, ref.guildId, premium, key, extended));
  return names;
}

const notFound = (error: any) =>
  error?.name === "NotFound" ||
  error?.name === "NoSuchKey" ||
  error?.$metadata?.httpStatusCode === 404;

async function collect(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export class AttachmentStore {
  constructor(
    private client: ObjectClient,
    private bucket: string,
    private encryptionSecret: string | undefined = process.env.FILE_ENCRYPTION_SECRET || undefined,
  ) {}

  get bucketName() {
    return this.bucket;
  }

  async find(ref: AttachmentRef, keys: string[] = []): Promise<FoundCopy[]> {
    const found: FoundCopy[] = [];
    for (const name of storedNames(ref, keys)) {
      try {
        // eslint-disable-next-line no-await-in-loop
        const head = await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: name }));
        const meta: Record<string, string> = head?.Metadata ?? {};
        const size = Number(meta.sz);
        found.push({
          name,
          size: Number.isSafeInteger(size) && size > 0 ? size : null,
          keyVersion: meta.kv === "2" ? 2 : 1,
          withheld: meta.withheld || null,
        });
      } catch (error) {
        if (!notFound(error)) throw error;
      }
    }
    return found;
  }

  /**
   * The original bytes of the first copy that can be decrypted, trying the
   * recorded size and then each of `sizes`. Null when there is no copy, or
   * none of the sizes opens it (`tried` says which were tried).
   */
  async read(
    ref: AttachmentRef,
    sizes: number[] = [],
  ): Promise<{ bytes: Buffer; size: number; name: string } | { bytes: null; tried: number[]; copies: number }> {
    const copies = (await this.find(ref)).filter((c) => !c.withheld);
    const tried: number[] = [];
    for (const copy of copies) {
      const candidates = [...new Set([copy.size, ...sizes].filter((s): s is number => !!s && s > 0))];
      for (const size of candidates) {
        tried.push(size);
        let keys: { key: string; iv: string };
        try {
          keys = FileStorage.prototype.getEncryptionKeys.call(
            { encryptionSecret: this.encryptionSecret },
            ref.guildId,
            ref.channelId,
            ref.attachmentId,
            size,
            copy.keyVersion,
          );
        } catch {
          continue; // version 2 without the secret
        }
        try {
          // eslint-disable-next-line no-await-in-loop
          const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: copy.name }));
          const body = res.Body as Readable;
          // eslint-disable-next-line no-await-in-loop
          const bytes = await collect(decryptStream(body, keys.key, keys.iv));
          if (bytes.length > 0) return { bytes, size, name: copy.name };
        } catch {
          // Wrong size: bad padding or not a compressed stream. Try the next.
        }
      }
    }
    return { bytes: null, tried, copies: copies.length };
  }

  /** Deletes every stored name of the copy; the names that were there. */
  async delete(ref: AttachmentRef, keys: string[] = []): Promise<string[]> {
    const there = (await this.find(ref, keys)).map((c) => c.name);
    for (const name of there) {
      // eslint-disable-next-line no-await-in-loop
      await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: name }));
    }
    return there;
  }
}

/**
 * One store per bucket, from the environment:
 *
 *   FILES_S3_URL, FILES_S3_REGION, FILES_S3_ACCESS_KEY_ID,
 *   FILES_S3_SECRET_ACCESS_KEY, and the buckets as FILES_BUCKETS, a comma
 *   list of `variant:bucket` (e.g. `main:files,pro:files-pro`).
 *
 * Empty when any is missing.
 */
export function attachmentStoresFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { variant: string; store: AttachmentStore }[] {
  const endpoint = env.FILES_S3_URL;
  const accessKeyId = env.FILES_S3_ACCESS_KEY_ID;
  const secretAccessKey = env.FILES_S3_SECRET_ACCESS_KEY;
  const buckets = (env.FILES_BUCKETS ?? "")
    .split(",")
    .map((pair) => pair.trim().split(":"))
    .filter((pair) => pair.length === 2 && pair[0] && pair[1]);
  if (!endpoint || !accessKeyId || !secretAccessKey || !buckets.length) return [];
  // Same addressing as FileStorage: the bucket named by its full address.
  const base = endpoint.replace(/\/?$/, "/");
  return buckets.map(([variant, bucket]) => ({
    variant,
    store: new AttachmentStore(
      new S3Client({
        endpoint: base,
        region: env.FILES_S3_REGION || "se-sto-1",
        bucketEndpoint: true,
        credentials: { accessKeyId, secretAccessKey },
      }),
      `${base}${bucket}`,
      env.FILE_ENCRYPTION_SECRET || undefined,
    ),
  }));
}
