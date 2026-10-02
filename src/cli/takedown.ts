#!/usr/bin/env node
/**
 * Delete the stored copy of one Discord attachment.
 *
 * For acting on a report of unlawful content or an erasure request: the stored
 * object is removed without being downloaded, decrypted or opened.
 *
 * The object name depends on whether the guild had Pro when the file was
 * saved and on whether it was stored with extended expiry, so all four
 * combinations are tried. Copies stored under a key prefix (assets such as
 * avatars) are only found when the key is named with `--key`.
 *
 * Usage, from inside a bot pod (the bot's S3 env vars are already set there):
 *
 *   node node_modules/file/dist/src/cli/takedown.js \
 *     --guild <id> --channel <id> --attachment <id> [--dry-run]
 *
 *   node node_modules/file/dist/src/cli/takedown.js \
 *     --guild <id> --url https://cdn.discordapp.com/attachments/<channel>/<attachment>/<name>
 *
 * `--key a,b` also tries the names stored under those key prefixes, using the
 * same three ids the object was saved with.
 *
 * `--bucket` overrides S3_FILES_BUCKET. Each bot variant has its own bucket,
 * so run this in the pod of the bot that is in the server.
 *
 * Env: S3_URI, S3_FILES_BUCKET, S3_ACCESS_KEY_ID, S3_ACCESS_KEY_SECRET,
 * S3_REGION.
 */
import {
  DeleteObjectCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import FileStorage from "../index.js";

type Options = Record<string, string | boolean>;

function parseArgs(argv: string[]): Options {
  const opts: Options = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (!key.startsWith("--")) continue;
    if (key === "--dry-run") opts.dryRun = true;
    else opts[key.slice(2)] = argv[++i];
  }
  return opts;
}

/** `.../attachments/<channel_id>/<attachment_id>/<filename>` */
function idsFromUrl(url: string) {
  const match = /\/attachments\/(\d+)\/(\d+)\//.exec(url);
  if (!match) throw new Error(`Not a Discord attachment URL: ${url}`);
  return { channel: match[1], attachment: match[2] };
}

/**
 * Every name one stored object can have: with and without Pro, with and
 * without extended expiry, unkeyed and under each given key prefix.
 */
function objectNames(
  guild: string,
  channel: string,
  attachment: string,
  keys: string[],
) {
  // getFileName does not read instance state, so no FileStorage is built: its
  // constructor rewrites the bucket's lifecycle rules.
  const name = FileStorage.prototype.getFileName as (
    attachment_id: string,
    channel_id: string,
    guild_id: string,
    quark_premium: boolean,
    key: string | null,
    extendedExpiration: boolean,
  ) => string;
  const names: string[] = [];
  for (const key of [null, ...keys]) {
    for (const extended of [false, true]) {
      for (const premium of [false, true]) {
        names.push(name(attachment, channel, guild, premium, key, extended));
      }
    }
  }
  return names;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const guild = opts.guild as string | undefined;
  let channel = opts.channel as string | undefined;
  let attachment = opts.attachment as string | undefined;
  if (typeof opts.url === "string") {
    ({ channel, attachment } = idsFromUrl(opts.url));
  }
  if (!guild || !channel || !attachment) {
    throw new Error(
      "Usage: takedown --guild <id> (--channel <id> --attachment <id> | --url <attachment url>) [--key <a,b>] [--bucket <name>] [--dry-run]",
    );
  }

  const keys =
    typeof opts.key === "string"
      ? opts.key.split(",").filter((key) => key !== "")
      : [];

  const s3Url = requireEnv("S3_URI");
  const bucket =
    typeof opts.bucket === "string"
      ? opts.bucket
      : requireEnv("S3_FILES_BUCKET");
  // Same client settings and bucket addressing as FileStorage.
  const client = new S3Client({
    endpoint: s3Url,
    credentials: {
      accessKeyId: requireEnv("S3_ACCESS_KEY_ID"),
      secretAccessKey: requireEnv("S3_ACCESS_KEY_SECRET"),
    },
    bucketEndpoint: true,
    region: requireEnv("S3_REGION"),
  });
  const Bucket = `${s3Url}${bucket}`;

  let found = 0;
  for (const Key of objectNames(guild, channel, attachment, keys)) {
    try {
      await client.send(new HeadObjectCommand({ Bucket, Key }));
    } catch (error: any) {
      if (
        error?.name === "NotFound" ||
        error?.$metadata?.httpStatusCode === 404
      ) {
        console.log(`not stored  ${bucket}/${Key}`);
        continue;
      }
      throw error;
    }
    found++;
    if (opts.dryRun) {
      console.log(`would delete ${bucket}/${Key}`);
      continue;
    }
    await client.send(new DeleteObjectCommand({ Bucket, Key }));
    console.log(`deleted     ${bucket}/${Key}`);
  }

  console.log(
    found === 0
      ? "No stored copy found under these names. It has expired, was already delivered, was never stored, or sits under a key prefix not passed with --key."
      : `${new Date().toISOString()} ${opts.dryRun ? "dry run" : "done"}: ${found} object(s).`,
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
