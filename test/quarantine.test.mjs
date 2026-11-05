/**
 * The quarantine store and what a match does with it: frames of animations,
 * the sealed write, the access log, expiry, the report reference, and the
 * export. S3 is an in-memory map; the matcher is a stand-in that answers
 * "match" for one chosen hash. No real abuse material is used anywhere: the
 * "matching" image is a generated pattern.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import sharp from "sharp";

const {
  Quarantine,
  QuarantineNotFound,
  quarantineFromEnv,
  reportFieldsOf,
  seal,
  unseal,
  openExport,
  parseKey,
} = await import("../dist/src/quarantine/index.js");
const { Scanner, framesToHash, pdqHashFrames, scanCredentialsSet, scannerFromEnv } =
  await import("../dist/src/scan/index.js");

const KEY = Buffer.alloc(32, 7);
const DAY = 24 * 60 * 60 * 1000;

/** An S3 bucket in a Map, answering the four commands the store sends. */
function memoryBucket() {
  const objects = new Map();
  const client = {
    objects,
    async send(command) {
      const name = command.constructor.name;
      const input = command.input;
      if (name === "PutObjectCommand") {
        objects.set(input.Key, Buffer.from(input.Body));
        return {};
      }
      if (name === "GetObjectCommand") {
        if (!objects.has(input.Key)) {
          const error = new Error("missing");
          error.name = "NoSuchKey";
          throw error;
        }
        return { Body: objects.get(input.Key) };
      }
      if (name === "DeleteObjectCommand") {
        objects.delete(input.Key);
        return {};
      }
      if (name === "ListObjectsV2Command") {
        return {
          Contents: [...objects.keys()]
            .filter((key) => key.startsWith(input.Prefix))
            .map((Key) => ({ Key })),
          IsTruncated: false,
        };
      }
      throw new Error(`unexpected ${name}`);
    },
  };
  return client;
}

function storeAt(clock) {
  const client = memoryBucket();
  const quarantine = new Quarantine({
    client,
    bucket: "quarantine",
    key: KEY,
    now: () => new Date(clock.t),
  });
  return { client, quarantine };
}

const detection = (extra = {}) => ({
  time: "2026-11-05T10:00:00.000Z",
  stage: "upload",
  source: "dashboard",
  provider: "test-matcher",
  category: "csam",
  match_type: "exact",
  pdq: Buffer.alloc(32, 1).toString("base64"),
  guild_id: "706552170241064981",
  user_id: "254307281023172608",
  route: "/api/servers/[guild_id]/bot-profile/image",
  ...extra,
});

const accessActions = (client) =>
  [...client.objects.keys()]
    .filter((key) => key.startsWith("access/"))
    .map((key) => JSON.parse(client.objects.get(key).toString()).action);

/** A pattern with plenty of detail, so its PDQ quality is high. */
function pattern(w, h, k) {
  const data = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 3;
      data[i] = (x * 7 * k + y * 3) % 256;
      data[i + 1] = ((x ^ y) * k * 5) % 256;
      data[i + 2] = (y * 11 + k * 40) % 256;
    }
  return data;
}

/** An animated GIF (or WebP) of `n` different frames. */
async function animation(n, format = "gif", w = 96, h = 64) {
  const frames = [];
  for (let k = 1; k <= n; k++) frames.push(pattern(w, h, k));
  return sharp(Buffer.concat(frames), {
    raw: { width: w, height: h * n, channels: 3, pageHeight: h },
  })
    .toFormat(format)
    .toBuffer();
}

/** Answers "match" for the hashes in `known`, "clear" for the rest. */
function stubMatcher(known = new Set(), { fail = false } = {}) {
  const asked = [];
  return {
    asked,
    name: "test-matcher",
    async lookup(hash) {
      asked.push(hash.toString("base64"));
      if (fail) throw new Error("unreachable");
      return known.has(hash.toString("base64"))
        ? { category: "csam", matchType: "exact", reference: "entry-1" }
        : null;
    },
  };
}

// ---------------------------------------------------------------- sealing

test("sealed objects open only with the key and under their own name", () => {
  const sealed = seal(KEY, "items/a/content", Buffer.from("bytes"));
  assert.equal(unseal(KEY, "items/a/content", sealed).toString(), "bytes");
  assert.throws(() => unseal(KEY, "items/b/content", sealed));
  assert.throws(() => unseal(Buffer.alloc(32, 8), "items/a/content", sealed));
  const flipped = Buffer.from(sealed);
  flipped[flipped.length - 1] ^= 1;
  assert.throws(() => unseal(KEY, "items/a/content", flipped));
});

test("the key is 32 bytes as hex or base64, and nothing else", () => {
  assert.equal(parseKey("07".repeat(32)).length, 32);
  assert.equal(parseKey(KEY.toString("base64")).length, 32);
  assert.throws(() => parseKey("short"));
});

test("not configured: no store", () => {
  assert.equal(quarantineFromEnv({}), undefined);
  assert.equal(
    quarantineFromEnv({ QUARANTINE_BUCKET: "q", S3_URI: "https://s3", S3_ACCESS_KEY_ID: "a", S3_ACCESS_KEY_SECRET: "b" }),
    undefined,
  );
  assert.ok(
    quarantineFromEnv({
      QUARANTINE_BUCKET: "q",
      QUARANTINE_KEY: KEY.toString("hex"),
      QUARANTINE_S3_URL: "https://garage.internal",
      QUARANTINE_S3_ACCESS_KEY_ID: "a",
      QUARANTINE_S3_SECRET_ACCESS_KEY: "b",
    }) instanceof Quarantine,
  );
});

// ---------------------------------------------------------------- the store

test("a write keeps the file and its data sealed, and logs it", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const content = Buffer.from("not really an image, only test bytes");
  const id = await quarantine.put({
    detection: detection(),
    content,
    contentType: "image/png",
    fileName: "a.png",
    subject: { user_id: "254307281023172608", guild_id: "706552170241064981", ip: "203.0.113.9" },
    relevantData: { session: { username: "someone" } },
  });
  assert.match(id, /^[a-z0-9]+-[0-9a-f]{12}$/);

  // Nothing in the bucket is readable without the key.
  for (const [name, body] of client.objects) {
    if (name.startsWith("access/")) {
      assert.ok(!body.toString().includes("203.0.113.9"), "no IP in the access log");
      continue;
    }
    assert.ok(!body.includes(content), `${name} holds the file in the clear`);
    assert.ok(!body.toString().includes("203.0.113.9"), `${name} holds the IP in the clear`);
  }
  assert.deepEqual(accessActions(client), ["write"]);

  const [summary] = await quarantine.list("admin:1");
  assert.equal(summary.id, id);
  assert.equal(summary.relevant_data, undefined, "the list leaves out the relevant data");
  assert.equal(summary.subject.ip, "203.0.113.9");
  assert.equal(summary.content.bytes, content.length);
  assert.equal(summary.expires_at, new Date(clock.t + 365 * DAY).toISOString());

  const full = await quarantine.get(id, "admin:1");
  assert.deepEqual(full.relevant_data, { session: { username: "someone" } });
  assert.deepEqual(accessActions(client).sort(), ["list", "read", "write"]);
});

test("unknown or malformed ids are not found", async () => {
  const { quarantine } = storeAt({ t: Date.now() });
  await assert.rejects(quarantine.get("../../etc", "admin:1"), QuarantineNotFound);
  await assert.rejects(quarantine.get("abc-000000000000", "admin:1"), QuarantineNotFound);
});

test("an unreported item is deleted after a year, and not before", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });

  clock.t += 364 * DAY;
  assert.equal((await quarantine.sweep()).items, 0);
  assert.ok(client.objects.has(`items/${id}/content`));

  clock.t += 2 * DAY;
  assert.equal((await quarantine.sweep()).items, 1);
  assert.ok(!client.objects.has(`items/${id}/content`));
  assert.ok(!client.objects.has(`items/${id}/record`));
  assert.ok(accessActions(client).includes("expire"));
});

test("a reported item is kept a year from the report, its reference five years", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });

  clock.t += 200 * DAY;
  const reportedAt = new Date(clock.t - DAY).toISOString();
  const record = await quarantine.recordReport(id, { reference: "NCA-123", reportedAt }, "admin:1");
  assert.equal(record.report.reference, "NCA-123");
  assert.equal(record.expires_at, new Date(Date.parse(reportedAt) + 365 * DAY).toISOString());

  // Past a year from detection, inside a year from the report: kept.
  clock.t = Date.parse("2026-11-05T10:00:00Z") + 400 * DAY;
  assert.equal((await quarantine.sweep()).items, 0);
  assert.ok(client.objects.has(`items/${id}/content`));

  // Past a year from the report: the item goes, the reference stays.
  clock.t = Date.parse(reportedAt) + 366 * DAY;
  const swept = await quarantine.sweep();
  assert.equal(swept.items, 1);
  assert.equal(swept.references, 0);
  const [kept] = await quarantine.references("admin:1");
  assert.equal(kept.reference, "NCA-123");

  // Five years from the report: the reference goes too.
  clock.t = Date.parse(reportedAt) + 5 * 365 * DAY + DAY;
  assert.equal((await quarantine.sweep()).references, 1);
  assert.deepEqual(await quarantine.references("admin:1"), []);
});

test("a report reference must be given, and dated in the past", async () => {
  const clock = { t: Date.now() };
  const { quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });
  await assert.rejects(quarantine.recordReport(id, { reference: " ", reportedAt: new Date().toISOString() }, "admin:1"));
  await assert.rejects(
    quarantine.recordReport(id, { reference: "R", reportedAt: new Date(clock.t + DAY).toISOString() }, "admin:1"),
  );
});

test("the export hands the file over sealed under a one-off key, and logs it", async () => {
  const { client, quarantine } = storeAt({ t: Date.now() });
  const content = Buffer.from("test bytes standing in for the file");
  const id = await quarantine.put({ detection: detection(), content, subject: {} });
  const exported = await quarantine.exportContent(id, "admin:1");
  assert.ok(!exported.sealed.includes(content));
  assert.deepEqual(openExport(exported.sealed, exported.key, exported.name), content);
  assert.notEqual(exported.key, KEY.toString("base64"));
  assert.ok(accessActions(client).includes("export_content"));
});

test("the report fields carry Schedule 1's items, and say what is not held", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const id = await quarantine.put({
    detection: detection({ stage: "store", source: "bot", channel_id: "1", attachment_id: "2" }),
    content: Buffer.from("x"),
    contentType: "image/png",
    subject: { user_id: "254307281023172608", guild_id: "706552170241064981", message_id: "3" },
  });
  const fields = await quarantine.reportFields(id, "admin:1");
  assert.equal(fields.detection.classification, "csam");
  assert.equal(fields.detection.pdq_hash_hex, "01".repeat(32));
  assert.equal(fields.user.discord_user_id, "254307281023172608");
  assert.equal(fields.user.account_created_at, "2016-12-02T18:06:20.596Z");
  assert.equal(fields.location.discord_message_id, "3");
  assert.equal(fields.upload.ip_address, null);
  assert.ok(fields.not_available.some((line) => line.startsWith("IP address")));
  assert.equal(typeof reportFieldsOf, "function");
});

// ---------------------------------------------------------------- frames

test("frames to hash: all up to the cap, then spread from first to last", () => {
  assert.deepEqual(framesToHash(1, 32), [0]);
  assert.deepEqual(framesToHash(5, 32), [0, 1, 2, 3, 4]);
  assert.deepEqual(framesToHash(100, 5), [0, 25, 50, 74, 99]);
  assert.deepEqual(framesToHash(9, 1), [0]);
});

for (const format of ["gif", "webp"]) {
  test(`every frame of an animated ${format} is checked, not just the first`, async () => {
    const image = await animation(6, format);
    const { frames, total } = await pdqHashFrames(image, 32);
    assert.equal(total, 6);
    assert.equal(frames.length, 6);
    assert.equal(new Set(frames.map((f) => f.hash.toString("base64"))).size, 6, "frames differ");

    // Only the fifth frame is "known".
    const known = frames[4].hash.toString("base64");
    const scanner = new Scanner({ matcher: stubMatcher(new Set([known])) });
    const verdict = await scanner.check(image);
    assert.equal(verdict.status, "match");
    assert.equal(verdict.frame, 4);
    assert.deepEqual(verdict.frames, { total: 6, checked: 6 });

    // Checking only the first frame would have missed it.
    const firstOnly = new Scanner({ matcher: stubMatcher(new Set([known])), maxFrames: 1 });
    assert.equal((await firstOnly.check(image)).status, "clear");
  });
}

test("past the frame cap, frames are spread out and the last one is checked", async () => {
  const image = await animation(10, "gif", 64, 48);
  const { frames, total } = await pdqHashFrames(image, 4);
  assert.equal(total, 10);
  assert.deepEqual(frames.map((f) => f.frame), [0, 3, 6, 9]);
});

test("one frame the matcher cannot answer for makes the whole file an error", async () => {
  const image = await animation(3);
  const scanner = new Scanner({ matcher: stubMatcher(new Set(), { fail: true }) });
  const verdict = await scanner.check(image);
  assert.deepEqual(verdict, { status: "error", reason: "matcher_unavailable" });
});

// ---------------------------------------------------------------- a match

test("a match is quarantined with the file, and the alert names the item but not the person's data", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const image = await animation(2);
  const { frames } = await pdqHashFrames(image, 32);
  const known = frames[1].hash.toString("base64");

  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return new Response(null, { status: 204 });
  };
  try {
    const scanner = new Scanner({
      matcher: stubMatcher(new Set([known])),
      quarantine,
      alertWebhook: "https://discord.test/api/webhooks/1/x",
    });
    const verdict = await scanner.check(image);
    assert.equal(verdict.status, "match");
    const id = await scanner.report(
      detection({ pdq: verdict.hash, frame: verdict.frame, hashes: verdict.hashes }),
      {
        content: image,
        contentType: "image/gif",
        subject: { user_id: "254307281023172608", guild_id: "706552170241064981", ip: "203.0.113.9" },
        relevantData: async () => ({ username: "someone" }),
      },
    );
    assert.ok(id);
    const record = await quarantine.get(id, "admin:1");
    assert.equal(record.detection.frame, 1);
    assert.deepEqual(record.relevant_data, { username: "someone" });
    assert.ok(client.objects.has(`items/${id}/content`));

    assert.equal(sent.length, 1);
    const alert = sent[0].body.content;
    assert.ok(alert.includes(id), "the alert names the quarantine item");
    assert.ok(!alert.includes("203.0.113.9"), "no IP in the alert");
    assert.ok(!alert.includes("someone"), "no relevant data in the alert");
    assert.ok(!/https?:\/\//.test(alert), "no link in the alert");

    // The same upload again is not kept twice.
    assert.equal(
      await scanner.report(detection({ pdq: verdict.hash }), { content: image }),
      undefined,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("with no quarantine, a match is still alerted, saying it was not kept", async () => {
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sent.push(JSON.parse(init.body));
    return new Response(null, { status: 204 });
  };
  try {
    const scanner = new Scanner({
      matcher: stubMatcher(),
      alertWebhook: "https://discord.test/api/webhooks/1/x",
    });
    assert.equal(await scanner.report(detection(), { content: Buffer.from("x") }), undefined);
    assert.match(sent[0].content, /NOT QUARANTINED/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("no credentials: no scanner, and the check reads as off", () => {
  assert.equal(scannerFromEnv({}), undefined);
  assert.equal(scanCredentialsSet({}), false);
  assert.equal(scanCredentialsSet({ ARACHNID_SHIELD_USERNAME: "u", ARACHNID_SHIELD_PASSWORD: "p" }), true);
});
