#!/usr/bin/env node
/**
 * Delete the stored copy of one Discord attachment.
 *
 * For acting on a report of unlawful content or an erasure request: the stored
 * object is removed without being downloaded, decrypted or opened.
 *
 * A message attachment is stored under one of two names, depending on whether
 * the guild had Pro when the file was saved. Both are tried.
 *
 * Usage, from inside a bot pod (the bot's S3 env vars are already set there):
 *
 *   node node_modules/file/dist/src/cli/takedown.js \
 *     --guild <id> --channel <id> --attachment <id> [--dry-run]
 *
 *   node node_modules/file/dist/src/cli/takedown.js \
 *     --guild <id> --url https://cdn.discordapp.com/attachments/<channel>/<attachment>/<name>
 *
 * `--bucket` overrides S3_FILES_BUCKET. Each bot variant has its own bucket,
 * so run this in the pod of the bot that is in the server.
 *
 * Env: S3_URI, S3_FILES_BUCKET, S3_ACCESS_KEY_ID, S3_ACCESS_KEY_SECRET,
 * S3_REGION.
 */
import { DeleteObjectCommand, HeadObjectCommand, S3Client, } from "@aws-sdk/client-s3";
import FileStorage from "../index.js";
function parseArgs(argv) {
    const opts = {};
    for (let i = 0; i < argv.length; i++) {
        const key = argv[i];
        if (!key.startsWith("--"))
            continue;
        if (key === "--dry-run")
            opts.dryRun = true;
        else
            opts[key.slice(2)] = argv[++i];
    }
    return opts;
}
/** `.../attachments/<channel_id>/<attachment_id>/<filename>` */
function idsFromUrl(url) {
    const match = /\/attachments\/(\d+)\/(\d+)\//.exec(url);
    if (!match)
        throw new Error(`Not a Discord attachment URL: ${url}`);
    return { channel: match[1], attachment: match[2] };
}
/** The two names one message attachment can be stored under. */
function objectNames(guild, channel, attachment) {
    // getFileName does not read instance state, so no FileStorage is built: its
    // constructor rewrites the bucket's lifecycle rules.
    const name = FileStorage.prototype.getFileName;
    return [false, true].map((premium) => name(attachment, channel, guild, premium));
}
function requireEnv(name) {
    const value = process.env[name];
    if (!value)
        throw new Error(`${name} is not set`);
    return value;
}
async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const guild = opts.guild;
    let channel = opts.channel;
    let attachment = opts.attachment;
    if (typeof opts.url === "string") {
        ({ channel, attachment } = idsFromUrl(opts.url));
    }
    if (!guild || !channel || !attachment) {
        throw new Error("Usage: takedown --guild <id> (--channel <id> --attachment <id> | --url <attachment url>) [--bucket <name>] [--dry-run]");
    }
    const s3Url = requireEnv("S3_URI");
    const bucket = typeof opts.bucket === "string"
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
    for (const Key of objectNames(guild, channel, attachment)) {
        try {
            await client.send(new HeadObjectCommand({ Bucket, Key }));
        }
        catch (error) {
            if (error?.name === "NotFound" ||
                error?.$metadata?.httpStatusCode === 404) {
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
    console.log(found === 0
        ? "No stored copy found. It has expired, was already delivered, or was never stored."
        : `${new Date().toISOString()} ${opts.dryRun ? "dry run" : "done"}: ${found} object(s).`);
}
main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
//# sourceMappingURL=takedown.js.map