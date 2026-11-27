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

test("an item not to be reported can be deleted, with a reason, unless reported or on hold", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });
  await assert.rejects(quarantine.deleteUnreported(id, "  ", "admin:1"));
  await quarantine.setHold(id, "Police request", "admin:1");
  await assert.rejects(quarantine.deleteUnreported(id, "not CSEA", "admin:1"), /legal hold/);
  await quarantine.setHold(id, null, "admin:1");
  await quarantine.deleteUnreported(id, "harmful-abusive-material: not reportable", "admin:1");
  assert.ok(![...client.objects.keys()].some((n) => n.startsWith(`items/${id}/`)));
  await assert.rejects(quarantine.get(id, "admin:1"), QuarantineNotFound);
  assert.ok(accessActions(client).includes("delete_unreported"));

  const reported = await quarantine.put({ detection: detection(), content: Buffer.from("y"), subject: {} });
  await quarantine.recordReport(reported, { reference: "NCA-REF-1", reportedAt: new Date(clock.t - 1000).toISOString() }, "admin:1");
  await assert.rejects(quarantine.deleteUnreported(reported, "mistake", "admin:1"), /one year/);
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

test("there is no way to export the file: it only ever goes to the NCA through the API", async () => {
  const { quarantine } = storeAt({ t: Date.now() });
  assert.equal(quarantine.exportContent, undefined);
});

test("the report fields carry Schedule 1's items in order, and say what is not held", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const id = await quarantine.put({
    detection: detection({
      stage: "store",
      source: "bot",
      channel_id: "1",
      attachment_id: "2",
      match_details: { classification: "csam", match_type: "exact" },
    }),
    content: Buffer.from("x"),
    contentType: "image/png",
    subject: {
      user_id: "254307281023172608",
      username: "someone",
      guild_id: "706552170241064981",
      guild_name: "Test server",
      message_id: "3",
    },
  });
  const fields = await quarantine.reportFields(id, "admin:1");
  assert.deepEqual(Object.keys(fields).slice(0, 7), [
    "1_reporting_service",
    "2_priority",
    "3_user",
    "4_content",
    "5_how_detected",
    "6_when_and_where",
    "7_relevant_data_two_weeks",
  ]);
  assert.equal(fields["5_how_detected"].classification, "csam");
  assert.deepEqual(fields["5_how_detected"].match_response, { classification: "csam", match_type: "exact" });
  assert.equal(fields["5_how_detected"].pdq_hash_hex, "01".repeat(32));
  assert.equal(fields["3_user"].discord_user_id, "254307281023172608");
  assert.equal(fields["3_user"].account_created_at, "2016-12-02T18:06:20.596Z");
  assert.equal(fields["3_user"].ip_address, null);
  assert.equal(fields["6_when_and_where"].discord_server_name, "Test server");
  assert.equal(fields["6_when_and_where"].discord_message_id, "3");
  assert.ok(fields.not_available.some((line) => line.startsWith("IP address: not available")));
  assert.equal(typeof reportFieldsOf, "function");
});

test("the report links the message and the profile, and the upload page for a dashboard upload", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const bot = await quarantine.put({
    detection: detection({ stage: "store", source: "bot", channel_id: "706552170241064982", attachment_id: "2" }),
    content: Buffer.from("x"),
    subject: { user_id: "254307281023172608", guild_id: "706552170241064981", message_id: "706552170241064983" },
  });
  const fields = await quarantine.reportFields(bot, "admin:1");
  assert.equal(
    fields["6_when_and_where"].url,
    "https://discord.com/channels/706552170241064981/706552170241064982/706552170241064983",
  );
  assert.equal(fields["3_user"].profile_url, "https://discord.com/users/254307281023172608");

  const upload = await quarantine.put({
    detection: detection(),
    content: Buffer.from("x"),
    subject: { user_id: "254307281023172608", route: "/dashboard/706552170241064981/bot-profile" },
  });
  assert.equal(
    (await quarantine.reportFields(upload, "admin:1"))["6_when_and_where"].url,
    "https://quark.bot/dashboard/706552170241064981/bot-profile",
  );

  const noMessage = await quarantine.put({
    detection: detection({ stage: "store", source: "bot", user_id: undefined }),
    content: Buffer.from("x"),
    subject: {},
  });
  const bare = await quarantine.reportFields(noMessage, "admin:1");
  assert.equal(bare["6_when_and_where"].url, null);
  assert.equal(bare["3_user"].profile_url, null);
});

test("a report says it relates to an earlier one about the same user or the same image", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { quarantine } = storeAt(clock);
  const first = await quarantine.put({
    detection: detection({ pdq: Buffer.alloc(32, 7).toString("base64"), guild_id: "500000000000000001" }),
    content: Buffer.from("a"),
    subject: { user_id: "254307281023172608" },
  });
  clock.t += 3600_000;
  await quarantine.recordReport(first, { reference: "NCA-1", reportedAt: new Date(clock.t).toISOString() }, "admin:1");
  const sameImage = await quarantine.put({
    detection: detection({ pdq: Buffer.alloc(32, 9).toString("base64"), user_id: "300000000000000001", guild_id: "500000000000000002" }),
    content: Buffer.from("b"),
    subject: { user_id: "300000000000000001" },
  });
  clock.t += 3600_000;
  await quarantine.recordReport(sameImage, { reference: "NCA-2", reportedAt: new Date(clock.t).toISOString() }, "admin:1");
  const unrelated = await quarantine.put({
    detection: detection({ pdq: Buffer.alloc(32, 3).toString("base64"), user_id: "300000000000000002", guild_id: "500000000000000003" }),
    content: Buffer.from("c"),
    subject: { user_id: "300000000000000002" },
  });
  await quarantine.recordReport(unrelated, { reference: "NCA-3", reportedAt: new Date(clock.t).toISOString() }, "admin:1");

  // Same user as the first, same image as the second.
  const now = await quarantine.put({
    detection: detection({ pdq: Buffer.alloc(32, 9).toString("base64"), guild_id: "500000000000000004" }),
    content: Buffer.from("d"),
    subject: { user_id: "254307281023172608" },
  });
  const previous = (await quarantine.reportFields(now, "admin:1"))["8_previous_reports"];
  assert.equal(previous.relates_to_previous_report, true);
  assert.deepEqual(
    previous.reports.map((r) => [r.reference, r.relates_by]),
    [["NCA-1", "same user"], ["NCA-2", "same image"]],
  );

  // The unrelated report relates to nothing earlier.
  const alone = await quarantine.reportFields(unrelated, "admin:1");
  assert.deepEqual(alone["8_previous_reports"], { relates_to_previous_report: false, reports: [] });

  // A reference outlives its item, and still matches by the user it kept.
  clock.t += 400 * 86400_000;
  await quarantine.sweep();
  const later = await quarantine.put({
    detection: detection({ pdq: Buffer.alloc(32, 5).toString("base64") }),
    content: Buffer.from("e"),
    subject: { user_id: "254307281023172608" },
  });
  assert.deepEqual(
    (await quarantine.reportFields(later, "admin:1"))["8_previous_reports"].reports.map((r) => r.reference),
    ["NCA-1"],
  );

});

test("the report carries the file's EXIF, or says there is none", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const withExif = await sharp(pattern(32, 32, 2), { raw: { width: 32, height: 32, channels: 3 } })
    .jpeg()
    .withExif({ IFD0: { Make: "TestCam", Model: "Model 1" } })
    .toBuffer();
  const id = await quarantine.put({ detection: detection(), content: withExif, subject: {} });
  const fields = await quarantine.reportFields(id, "admin:1");
  assert.equal(fields["4_content"].exif.tags.Make, "TestCam");
  assert.equal(fields["4_content"].exif.tags.Model, "Model 1");
  assert.ok(fields["4_content"].exif.raw_base64.length > 0);
  assert.ok(!fields.not_available.some((line) => line.startsWith("EXIF")));

  const plain = await sharp(pattern(32, 32, 2), { raw: { width: 32, height: 32, channels: 3 } }).png().toBuffer();
  const bare = await quarantine.put({ detection: detection(), content: plain, subject: {} });
  const none = await quarantine.reportFields(bare, "admin:1");
  assert.deepEqual(none["4_content"].exif, { tags: null, raw_base64: null });
  assert.ok(none.not_available.includes("EXIF data: none in the file"));
});

test("billing records from the app go in the report, and decide what is said to be not held", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: { user_id: "254307281023172608" } });

  const unchecked = await quarantine.reportFields(id, "admin:1");
  assert.equal(unchecked["3_user"].billing, null);
  assert.ok(unchecked.not_available.includes("Billing details: not checked"));

  const never = await quarantine.reportFields(id, "admin:1", { billing: [] });
  assert.deepEqual(never["3_user"].billing, []);
  assert.ok(never.not_available.some((line) => line.startsWith("Billing name, address, email and phone: the user has never paid")));

  const record = {
    source: "Stripe customer cus_1",
    name: "A Person",
    email: "a@example.com",
    phone: null,
    address: { line1: "1 Street", city: "Town", postal_code: "AB1 2CD", country: "GB" },
    payment_methods: [{ type: "card", name: "A Person", email: null, phone: null, address: null }],
  };
  const paid = await quarantine.reportFields(id, "admin:1", { billing: [record] });
  assert.deepEqual(paid["3_user"].billing, [record]);
  assert.ok(!paid.not_available.some((line) => line.startsWith("Email")));
  assert.ok(paid.not_available.includes("Telephone number: not on the user's billing records"));

  const down = await quarantine.reportFields(id, "admin:1", { billingError: "Stripe did not answer" });
  assert.equal(down["3_user"].billing, null);
  assert.ok(down.not_available.includes("Billing details: could not be checked (Stripe did not answer)"));
});

test("priority: one of three levels, recorded, logged, and in the report", async () => {
  const { client, quarantine } = storeAt({ t: Date.now() });
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });
  assert.equal((await quarantine.reportFields(id, "admin:1"))["2_priority"].level, null);
  await assert.rejects(quarantine.setPriority(id, "whenever", "admin:1"));
  const record = await quarantine.setPriority(id, "immediate_risk", "admin:1");
  assert.equal(record.priority.level, "immediate_risk");
  assert.equal(record.priority.set_by, "admin:1");
  const fields = await quarantine.reportFields(id, "admin:1");
  assert.match(fields["2_priority"].meaning, /call 999 first/);
  assert.ok(accessActions(client).includes("set_priority"));
});

test("the two weeks of relevant data are snapshotted: at the match, and parts added after", async () => {
  const { client, quarantine } = storeAt({ t: Date.now() });
  const atMatch = {
    window: { from: "2026-10-22T10:00:00.000Z", to: "2026-11-05T10:00:00.000Z" },
    cached_messages: [{ id: "9", content: "hello", attachments: [{ id: "2", name: "a.png", size: 10 }] }],
  };
  const id = await quarantine.put({
    detection: detection(), content: Buffer.from("x"), subject: {}, relevantData: atMatch,
  });
  await quarantine.addRelevantData(id, "website", { log_archive: { rows: [{ log_id: "L1" }] } }, "system:website");
  await assert.rejects(quarantine.addRelevantData(id, "../x", {}, "system:website"));
  for (const [name, body] of client.objects)
    if (!name.startsWith("access/")) assert.ok(!body.toString().includes("hello"), `${name} in the clear`);
  const item = await quarantine.get(id, "admin:1");
  assert.deepEqual(item.relevant_data, atMatch);
  assert.deepEqual(item.relevant_data_parts.website, { log_archive: { rows: [{ log_id: "L1" }] } });
  // The list never carries it.
  const [summary] = await quarantine.list("admin:1");
  assert.equal(summary.relevant_data, undefined);
  assert.ok(accessActions(client).includes("add_relevant_data"));
});

test("the report as submitted is kept with its reference, and a hold stops expiry", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });
  await quarantine.recordReport(id, { reference: "NCA-9", reportedAt: new Date(clock.t).toISOString() }, "admin:1");
  const item = await quarantine.get(id, "admin:1");
  assert.equal(item.submitted.reference, "NCA-9");
  assert.ok(item.submitted.report["5_how_detected"], "the fields as they stood");

  await assert.rejects(quarantine.setHold(id, "  ", "admin:1"));
  await quarantine.setHold(id, "Police request, ref 123", "admin:1");
  clock.t += 6 * 365 * DAY;
  const held = await quarantine.sweep();
  assert.equal(held.items, 0);
  assert.equal(held.references, 0);
  assert.ok(client.objects.has(`items/${id}/content`));
  // Lifted: it goes, everything under it.
  await quarantine.setHold(id, null, "admin:1");
  const swept = await quarantine.sweep();
  assert.equal(swept.items, 1);
  assert.equal(swept.references, 1);
  assert.deepEqual([...client.objects.keys()].filter((k) => k.startsWith("items/")), []);
  assert.ok(accessActions(client).includes("set_hold"));
});

test("every access is logged, append-only, with who, what and when", async () => {
  const { client, quarantine } = storeAt({ t: Date.parse("2026-11-05T10:00:00Z") });
  const id = await quarantine.put({ detection: detection(), content: Buffer.from("x"), subject: {} });
  await quarantine.list("admin:1");
  await quarantine.get(id, "admin:1");
  await quarantine.reportFields(id, "admin:2");
  await quarantine.setPriority(id, "other", "admin:2");
  const names = [...client.objects.keys()].filter((k) => k.startsWith("access/"));
  assert.equal(names.length, 5, "one object per access, none overwritten");
  const entries = names.map((n) => JSON.parse(client.objects.get(n).toString()));
  assert.deepEqual(
    entries.map((e) => [e.actor, e.action]).sort(),
    [["admin:1", "list"], ["admin:1", "read"], ["admin:2", "export_fields"], ["admin:2", "set_priority"], ["system:dashboard", "write"]].sort(),
  );
  for (const e of entries) assert.match(e.time, /^2026-11-05T/);
  const log = await quarantine.accessLog("admin:1");
  assert.equal(log.length, 5);
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

test("the start-up self-test logs one line: LIVE, or NOT LIVE with the reason", async () => {
  const lines = [];
  const log = console.log;
  const error = console.error;
  console.log = (line) => lines.push(line);
  console.error = (line) => lines.push(line);
  try {
    const live = new Scanner({ matcher: stubMatcher(), quarantine: {} });
    assert.equal(await live.selfTest("website"), true);
    const refused = new Scanner({
      matcher: { name: "arachnid-shield", lookup: async () => { throw new Error("Arachnid Shield answered 401"); } },
      quarantine: {},
    });
    assert.equal(await refused.selfTest("serverlog"), false);
  } finally {
    console.log = log;
    console.error = error;
  }
  assert.match(lines[0], /^\[FILE SCAN\] LIVE in website: hashing works and test-matcher accepted the credentials/);
  assert.match(lines[1], /^\[FILE SCAN\] NOT LIVE in serverlog, images cannot be checked: Arachnid Shield answered 401/);
});

test("the object store for log avatars puts, gets and deletes, and is off when not configured", async () => {
  const { ObjectStore, objectStoreFromEnv } = await import("../dist/src/objects/index.js");
  assert.equal(objectStoreFromEnv("LOG_AVATAR", {}), undefined);
  const client = memoryBucket();
  const realSend = client.send;
  client.send = async (command) => {
    const answer = await realSend(command);
    const bytes = answer.Body;
    if (bytes) answer.Body = { transformToByteArray: async () => bytes };
    return answer;
  };
  const store = new ObjectStore(client, "avatars");
  await store.put("log-avatars/1/abc.png", Buffer.from("png"), "image/png");
  assert.equal((await store.get("log-avatars/1/abc.png")).toString(), "png");
  assert.equal(await store.get("log-avatars/1/none.png"), null);
  assert.equal(await store.delete("log-avatars/1/abc.png"), true);
  assert.equal(await store.get("log-avatars/1/abc.png"), null);
  assert.equal(await store.delete("log-avatars/1/abc.png"), false);
});

// ---------------------------------------------------------------- NCA API

const NCA = {
  apiKey: "k",
  orgId: "989d7cc4-60f4-42bf-b65b-843c4ee09e5a",
  baseUrl: "https://nca.test/submission",
  espName: "Quark Bot Limited",
  reporter: { firstName: "A", lastName: "B", email: "a@b.test", phone: "", phoneCountryCode: "+44" },
};

function ncaFetch(answer) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const form = init.body;
    calls.push({
      url,
      headers: init.headers,
      submission: JSON.parse(form.get("submission")),
      files: form.getAll("uploadedFiles").map((f) => ({ name: f.name, size: f.size })),
    });
    return typeof answer === "function" ? answer() : answer;
  };
  return { calls, fetchImpl };
}

const ok = () =>
  new Response(JSON.stringify({ success: true, referralID: "f6dec685-7474-41b5-9f05-f39e970e4b3a", referralFriendlyID: "SR-CSEAIRP-1257", reportID: 12345 }), { status: 201 });

test("NCA: a match is submitted with the file from the store, and the reference recorded", async () => {
  const { client, quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const content = Buffer.from("test bytes standing in for the file");
  const id = await quarantine.put({
    detection: detection({ stage: "store", source: "bot", category: "csam", channel_id: "706552170241064982", attachment_id: "706552170241064983", user_id: "301655085954367492" }),
    content,
    contentType: "image/png",
    fileName: "a.png",
    subject: { guild_id: "706552170241064981", message_id: "706552170241064984", username: "someone" },
  });
  const { calls, fetchImpl } = ncaFetch(ok);
  const { record, result } = await quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl }, { billing: [] });
  assert.equal(result.referralFriendlyID, "SR-CSEAIRP-1257");
  assert.equal(record.report.reference, "SR-CSEAIRP-1257");
  assert.equal(record.report.via_api.referral_id, "f6dec685-7474-41b5-9f05-f39e970e4b3a");
  const [call] = calls;
  assert.equal(call.url, "https://nca.test/submission/api/referral/");
  assert.equal(call.headers["X-API-KEY"], "k");
  assert.equal(call.headers.orgId, NCA.orgId);
  assert.deepEqual(call.files, [{ name: "a.png", size: content.length }, { name: "quark-report.json", size: call.files[1].size }]);
  const sub = call.submission;
  assert.equal(sub.priorityId, "3");
  assert.equal(sub.reportedInformation.incidentSummary.espEscalation, "Priority 3 - other");
  assert.equal(sub.reportedInformation.incidentSummary.methodOfDetection, "An automated detection tool");
  assert.equal(sub.reportedInformation.reportedPeople.reportedPerson[0].espUserId, "301655085954367492");
  assert.equal(sub.reportedInformation.uploadedFiles.uploadedFile[0].links.link[0].href, "https://discord.com/channels/706552170241064981/706552170241064982/706552170241064984");
  assert.match(sub.reportedInformation.uploadedFiles.uploadedFile[0].originalFileHashes.originalFileHash[0].value, /^SHA-256: /);
  assert.ok(accessActions(client).includes("submit_nca"));
  await assert.rejects(quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl }), /Already reported/);
});

test("NCA: a 400 is kept on the item and stops automatic reporting; a 5xx does not", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
  const down = ncaFetch(() => new Response("busy", { status: 503 }));
  await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl: down.fetchImpl }));
  let [rec] = await quarantine.list("admin:1");
  assert.equal(rec.nca.error.permanent, false);
  assert.equal(quarantine.autoReportBlocker(rec), null);
  const bad = ncaFetch(() => new Response('{"status":400,"message":"bad"}', { status: 400 }));
  await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl: bad.fetchImpl }));
  [rec] = await quarantine.list("admin:1");
  assert.match(quarantine.autoReportBlocker(rec), /refused/);
});

test("NCA: only failures the NCA certainly did not process are retried", async () => {
  const cases = [
    [408, "retry"], [429, "retry"], [503, "retry"],
    [401, "refused"], [403, "refused"], [500, "uncertain"], [502, "uncertain"], [504, "uncertain"],
    [400, "refused"], [404, "refused"], [413, "refused"], [415, "refused"], [422, "refused"],
  ];
  for (const [status, kind] of cases) {
    const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
    const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
    const { fetchImpl } = ncaFetch(() => new Response("{}", { status }));
    await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl }));
    const [rec] = await quarantine.list("admin:1");
    assert.equal(rec.nca.error.permanent, kind !== "retry", `${status}`);
    assert.equal(!!rec.nca.error.uncertain, kind === "uncertain", `${status}`);
    const blocker = quarantine.autoReportBlocker(rec);
    if (kind === "retry") assert.equal(blocker, null, `${status}`);
    else if (kind === "uncertain") assert.match(blocker, /may have reached the NCA.*Previously submitted reports/, `${status}`);
    else assert.match(blocker, /refused/, `${status}`);
  }
});

test("NCA: network failures are retried only if nothing can have been sent", async () => {
  const fail = (code) => async () => {
    throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error(code), { code }) });
  };
  for (const [code, uncertain] of [["ENOTFOUND", false], ["ECONNREFUSED", false], ["ECONNRESET", true], ["UND_ERR_SOCKET", true]]) {
    const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
    const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
    await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl: fail(code) }));
    const [rec] = await quarantine.list("admin:1");
    assert.equal(rec.nca.error.permanent, uncertain, code);
  }
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
  const { fetchImpl } = ncaFetch(() => new Response('{"success":true}', { status: 200 }));
  await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl }));
  const [rec] = await quarantine.list("admin:1");
  assert.equal(rec.nca.error.uncertain, true, "a 200 with no referral number may still have been received");
});

test("NCA: what is not reported automatically, and why", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const csam = await quarantine.put({ detection: detection({ category: "csam", attachment_id: "9" }), content: Buffer.from("x"), subject: {} });
  const ham = await quarantine.put({ detection: detection({ category: "harmful-abusive-material" }), content: Buffer.from("y"), subject: {} });
  const intake = await quarantine.put({
    detection: detection({ category: "csam" }),
    content: null,
    subject: { guild_id: "1" },
    intake: { route: "email", recorded_by: "admin:1", recorded_at: "2026-11-05T10:05:00Z", auto_report: false },
  });
  const all = await quarantine.list("admin:1");
  const by = (id) => all.find((r) => r.id === id);
  assert.equal(quarantine.autoReportBlocker(by(csam), all), null);
  assert.match(quarantine.autoReportBlocker(by(ham), all), /harmful-abusive-material/);
  assert.match(quarantine.autoReportBlocker(by(intake), all), /by hand/);
  assert.equal(by(intake).content.stored, false);
  await quarantine.setAutoReport(csam, "checking with the solicitor", "admin:1");
  const [paused] = (await quarantine.list("admin:1")).filter((r) => r.id === csam);
  assert.match(quarantine.autoReportBlocker(paused), /paused: checking/);
});

test("NCA: the same attachment matched twice (store, then re-upload) is reported once", async () => {
  const clock = { t: Date.parse("2026-11-05T10:05:00Z") };
  const { quarantine } = storeAt(clock);
  const first = await quarantine.put({ detection: detection({ category: "csam", attachment_id: "9" }), content: Buffer.from("x"), subject: {} });
  clock.t += 60_000;
  const second = await quarantine.put({ detection: detection({ category: "csam", attachment_id: "9", stage: "reupload" }), content: Buffer.from("x"), subject: {} });
  const all = await quarantine.list("admin:1");
  assert.equal(quarantine.autoReportBlocker(all.find((r) => r.id === first), all), null);
  assert.equal(quarantine.autoReportBlocker(all.find((r) => r.id === second), all), `same file as ${first}`);
});

test("NCA: main and Pro copying the same attachment at the same moment report it once", async () => {
  const clock = { t: Date.parse("2026-11-05T10:05:00Z") };
  const { quarantine } = storeAt(clock);
  const a = await quarantine.put({ detection: detection({ category: "csam", attachment_id: "77", provider: "main" }), content: Buffer.from("x"), subject: {} });
  const b = await quarantine.put({ detection: detection({ category: "csam", attachment_id: "77", provider: "pro" }), content: Buffer.from("x"), subject: {} });
  const all = await quarantine.list("admin:1");
  const blockers = [a, b].map((id) => quarantine.autoReportBlocker(all.find((r) => r.id === id), all));
  assert.equal(blockers.filter((x) => x === null).length, 1);
  const kept = [a, b].sort()[0];
  assert.equal(blockers[[a, b].indexOf(kept)], null);
});

test("NCA API key: stored sealed, shown only by its last four, reminders sent once", async () => {
  const clock = { t: Date.parse("2026-11-14T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  assert.equal(await quarantine.ncaApiKeyStatus(), null);
  await assert.rejects(quarantine.setNcaApiKey("abc def", new Date("2027-05-14"), "admin:1"));
  await assert.rejects(quarantine.setNcaApiKey("key-1234", new Date("2026-11-01"), "admin:1"));
  const status = await quarantine.setNcaApiKey(" secret-key-9876 ", new Date("2027-05-14T00:00:00Z"), "admin:1");
  assert.deepEqual(status, { set_at: "2026-11-14T10:00:00.000Z", set_by: "admin:1", expires_at: "2027-05-14T00:00:00.000Z", last4: "9876" });
  assert.equal((await quarantine.ncaApiKey()).api_key, "secret-key-9876");
  const raw = [...client.objects.entries()].filter(([name]) => !name.startsWith("access/")).map(([, body]) => Buffer.from(body).toString("latin1")).join();
  assert.ok(!raw.includes("secret-key"), "the key is never stored in the clear");
  const log = await quarantine.accessLog("admin:1");
  assert.ok(log.some((e) => e.action === "set_nca_api_key" && !JSON.stringify(e).includes("secret-key")));
  assert.equal(await quarantine.markNcaKeyReminder(status.set_at, 30), true);
  assert.equal(await quarantine.markNcaKeyReminder(status.set_at, 30), false);
  assert.equal(await quarantine.markNcaKeyReminder("2026-01-01T00:00:00.000Z", 14), false);
});

test("the register keeps a case sealed, survives its items, and expires after six years", async () => {
  const clock = { t: Date.parse("2026-11-15T10:00:00Z") };
  const { client, quarantine } = storeAt(clock);
  const entry = {
    id: "case-abc",
    opened_at: "2026-11-15T09:00:00.000Z",
    updated_at: "2026-11-15T09:30:00.000Z",
    route: "image check",
    reporter: "image check",
    type: "A",
    allegation: "Two hash matches in one server.",
    items: [
      { quarantine_id: "q1", detected_at: "2026-11-15T09:00:00.000Z", category: "harmful-abusive-material", outcome: "cleared", reason: "below threshold" },
    ],
  };
  await quarantine.putRegister(entry, "admin:1");
  const sealed = client.objects.get("register/case-abc");
  assert.ok(sealed && !sealed.toString("utf8").includes("server"), "sealed");
  assert.deepEqual(await quarantine.register("admin:1"), [entry]);
  await assert.rejects(() => quarantine.putRegister({ ...entry, id: "../x" }, "admin:1"), /Bad register id/);
  assert.ok((await quarantine.accessLog("admin:1")).some((e) => e.action === "write_register"));

  clock.t = Date.parse("2032-11-10T00:00:00Z");
  await quarantine.sweep();
  assert.equal((await quarantine.register("admin:1")).length, 1, "kept inside six years");
  clock.t = Date.parse("2032-11-20T00:00:00Z");
  await quarantine.sweep();
  assert.equal((await quarantine.register("admin:1")).length, 0, "gone after six years");
  assert.ok((await quarantine.accessLog("admin:1")).some((e) => e.action === "expire_register"));
});

test("NCA payload: date-times as in the NCA's examples, phone numbers as digits", async () => {
  const { phoneOf } = await import("../dist/src/quarantine/nca.js");
  assert.deepEqual(phoneOf("07700 900123", "+44"), { countryCallingCode: "+44", value: "7700900123" });
  assert.deepEqual(phoneOf("+44 7700 900123", "+44"), { countryCallingCode: "+44", value: "7700900123" });
  assert.deepEqual(phoneOf("+1 (555) 010-9999"), { countryCallingCode: "", value: "15550109999" });
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
  const { fetchImpl, calls } = ncaFetch(() => new Response(JSON.stringify({ referralID: "r", referralFriendlyID: "SR-1" }), { status: 201 }));
  await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl });
  const json = JSON.stringify(calls[0].submission);
  const dates = [...json.matchAll(/"(?:incidentDateTime|uploadedDateTime|verificationDate|dateTime|dateOfBirth|billingDateOfBirth|dateAccountClosed)":"([^"]+)"/g)].map((m) => m[1]);
  assert.ok(dates.length > 0);
  for (const d of dates) assert.match(d, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/, d);
  assert.match(json, /All dates and times in this report are UTC/);
});

test("NCA API key: what is saved on the dashboard is what goes in X-API-KEY, byte for byte", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-19T10:00:00Z") });
  const key = "AbC123-xyz_./+=~9876";
  await quarantine.setNcaApiKey(`  ${key}\n`, new Date("2027-05-19T00:00:00Z"), "admin:1");
  const stored = await quarantine.ncaApiKey();
  assert.equal(stored.api_key, key, "only surrounding whitespace is removed");
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
  const { fetchImpl, calls } = ncaFetch(() => new Response(JSON.stringify({ referralID: "r", referralFriendlyID: "SR-1" }), { status: 201 }));
  await quarantine.submitToNca(id, "admin:1", { ...NCA, apiKey: stored.api_key, fetchImpl });
  const headers = new Headers(calls[0].headers);
  assert.equal(headers.get("x-api-key"), key);
  assert.equal(headers.get("orgid"), NCA.orgId);
});

test("NCA submission: one uploadedFile entry per attached file, named as attached", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-19T10:00:00Z") });
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: Buffer.from("x"), subject: {} });
  const { fetchImpl, calls } = ncaFetch(() => new Response(JSON.stringify({ referralID: "r", referralFriendlyID: "SR-1" }), { status: 201 }));
  await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl });
  const listed = calls[0].submission.reportedInformation.uploadedFiles.uploadedFile.map((f) => f.originalFilename);
  const attached = calls[0].files.map((f) => f.name);
  assert.deepEqual(listed, attached);
  assert.equal(attached.at(-1), "quark-report.json");
  const json = calls[0].submission.reportedInformation.uploadedFiles.uploadedFile.at(-1);
  assert.match(json.originalFileHashes.originalFileHash[0].value, /^SHA-256: [0-9a-f]{64}$/);
  assert.match(json.uploadedDateTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/);
});

// ------------------------------------------- NCA: the file, and follow-ups

const GIF = Buffer.concat([Buffer.from("GIF89a"), Buffer.alloc(40, 1), Buffer.from([0x3b])]);
const typedFetch = (answer) => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const form = init.body;
    calls.push({
      submission: JSON.parse(form.get("submission")),
      files: form.getAll("uploadedFiles").map((f) => ({ name: f.name, type: f.type, size: f.size })),
    });
    return answer();
  };
  return { calls, fetchImpl };
};
let refN = 400;
const okN = () => {
  refN++;
  return new Response(JSON.stringify({ success: true, referralID: `id-${refN}`, referralFriendlyID: `SR-CSEAIRP-${refN}` }), { status: 201 });
};
const putGif = (quarantine, extra = {}) =>
  quarantine.put({ detection: detection({ category: "csam" }), content: GIF, contentType: "image/png", fileName: "wéird name ✨.png", subject: {}, ...extra });

test("NCA: the file is named and typed from its own bytes, and the report carries the declaration", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await putGif(quarantine, { relevantData: { messages: [{ content: "hello" }] } });
  const { calls, fetchImpl } = typedFetch(okN);
  await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl });
  const [call] = calls;
  assert.deepEqual(call.files[0], { name: "w_ird_name.gif", type: "image/gif", size: GIF.length });
  assert.equal(call.submission.reportedInformation.uploadedFiles.uploadedFile[0].originalFilename, "w_ird_name.gif");
  const lines = call.submission.reportedInformation.additionalInformation.map((l) => l.value);
  assert.ok(lines.some((l) => /^Declaration \(SI 2026\/268, Schedule 1, item 5\)/.test(l)));
  assert.ok(lines.some((l) => /^Relevant data, two weeks before \(JSON, part 1 of 1\): .*hello/.test(l)));
});

test("NCA: a missing or altered file stops the report instead of sending it without the file", async () => {
  for (const spoil of ["delete", "alter"]) {
    const { client, quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
    const id = await putGif(quarantine);
    if (spoil === "delete") client.objects.delete(`items/${id}/content`);
    else client.objects.set(`items/${id}/content`, seal(KEY, `items/${id}/content`, Buffer.concat([GIF, Buffer.from("x")])));
    const { calls, fetchImpl } = typedFetch(okN);
    await assert.rejects(quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl }), { name: "NcaLocalError" });
    assert.equal(calls.length, 0, spoil);
    const [rec] = await quarantine.list("admin:1");
    assert.equal(rec.nca.error.local, true);
    assert.equal(rec.nca.error.permanent, true);
    assert.match(quarantine.autoReportBlocker(rec), /^not sent: the stored file (is missing|does not match)/);
  }
});

test("NCA: a file shorter than Discord declared, or not ending properly, is sent with a note", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await putGif(quarantine, { declaredBytes: GIF.length + 100 });
  const cut = await putGif(quarantine, { content: GIF.subarray(0, 20) });
  const { calls, fetchImpl } = typedFetch(okN);
  await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl });
  await quarantine.submitToNca(cut, "admin:1", { ...NCA, fetchImpl });
  const lines = (c) => c.submission.reportedInformation.additionalInformation.map((l) => l.value).join("\n");
  assert.match(lines(calls[0]), new RegExp(`holds ${GIF.length} bytes of the ${GIF.length + 100} Discord declared`));
  assert.match(lines(calls[1]), /does not end the way its format requires/);
  assert.equal(calls[1].files[0].size, 20);
});

test("NCA: sent without the file, then the file follows in a supplementary report", async () => {
  const { client, quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await putGif(quarantine);
  const { calls, fetchImpl } = typedFetch(okN);
  await assert.rejects(quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl }, {}, { withoutFile: " " }), /reason/);
  const first = await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl }, {}, { withoutFile: "the NCA's service refused the file (HTTP 403)" });
  assert.deepEqual(calls[0].files.map((f) => f.name), ["quark-report.json"]);
  assert.match(calls[0].submission.reportedInformation.additionalInformation[0].value, /^The reported file is NOT attached: the NCA's service refused/);
  assert.equal(first.record.report.file_not_sent, "the NCA's service refused the file (HTTP 403)");
  const ref = first.record.report.reference;

  const { record } = await quarantine.submitSupplementary(id, "admin:1", { ...NCA, fetchImpl });
  assert.deepEqual(calls[1].files.map((f) => f.name), ["w_ird_name.gif", "quark-report.json"]);
  assert.ok(calls[1].submission.reportedInformation.incidentSummary.relatedPreviousReferrals.split(",").includes(ref));
  assert.match(calls[1].submission.reportedInformation.additionalInformation[0].value, new RegExp(`^Supplementary report to ${ref}`));
  assert.equal(record.supplementary.length, 1);
  assert.equal(record.report.file_not_sent, undefined);
  assert.ok(client.objects.has(`items/${id}/submitted-1`));
  assert.ok(accessActions(client).includes("submit_nca_supplementary"));
  await assert.rejects(quarantine.submitSupplementary(id, "admin:1", { ...NCA, fetchImpl }), /Nothing to supplement/);
});

test("NCA: media the NCA says did not upload is marked, then sent again", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await putGif(quarantine);
  const { calls, fetchImpl } = typedFetch(okN);
  await assert.rejects(quarantine.markMediaMissing(id, "x", "admin:1"), /Not reported/);
  const { record: sent } = await quarantine.submitToNca(id, "admin:1", { ...NCA, fetchImpl });
  const marked = await quarantine.markMediaMissing(id, "NCA email 22 Nov", "admin:1");
  assert.equal(marked.report.media_missing.note, "NCA email 22 Nov");
  const { record } = await quarantine.submitSupplementary(id, "admin:1", { ...NCA, fetchImpl });
  assert.match(calls[1].submission.reportedInformation.additionalInformation[0].value, new RegExp(`the NCA said the media of ${sent.report.reference} did not all upload`));
  assert.equal(record.report.media_missing, undefined);
  assert.equal(record.supplementary[0].reference, `SR-CSEAIRP-${refN}`);
});

test("NCA: a report recorded by hand is not sent automatically until its priority is set", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await quarantine.put({
    detection: detection({ category: "csam" }),
    content: null,
    subject: {},
    intake: { route: "email", recorded_by: "admin:1", recorded_at: "2026-11-05T10:00:00Z", auto_report: true },
  });
  let [rec] = await quarantine.list("admin:1");
  assert.match(quarantine.autoReportBlocker(rec), /set the priority first/);
  await quarantine.setPriority(id, "other", "admin:1");
  [rec] = await quarantine.list("admin:1");
  assert.equal(quarantine.autoReportBlocker(rec), null);
});

// ------------------------------- NCA: the same uploader's other matches

test("NCA: a csam report carries the same uploader's harmful-abusive matches, which are then kept", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const by = (user, category, extra = {}) =>
    quarantine.put({ detection: detection({ category, user_id: user }), content: GIF, contentType: "image/gif", fileName: "x.gif", subject: { user_id: user, guild_id: "1", channel_id: "2", message_id: "3" }, ...extra });
  const csam = await by("100000000000000001", "csam");
  const mine = await by("100000000000000001", "harmful-abusive-material");
  const theirs = await by("100000000000000002", "harmful-abusive-material");
  const { calls, fetchImpl } = typedFetch(okN);
  const { record } = await quarantine.submitToNca(csam, "system:auto-report", { ...NCA, fetchImpl });
  const [call] = calls;
  assert.deepEqual(call.files.map((f) => f.name), ["x.gif", "quark-report.json", "other-match-1-x.gif"]);
  const entries = call.submission.reportedInformation.uploadedFile ?? call.submission.reportedInformation.uploadedFiles.uploadedFile;
  assert.equal(entries.length, 3);
  assert.equal(entries[2].originalFilename, "other-match-1-x.gif");
  assert.match(entries[2].additionalInformation[0].value, /reg\. 6\(4\)\(d\).*harmful-abusive-material.*Not assessed under UK law and not viewed by Quark/);
  const lines = call.submission.reportedInformation.additionalInformation.map((l) => l.value).join("\n");
  assert.match(lines, /1 further match from the same uploader/);
  const all = await quarantine.list("admin:1");
  const m = all.find((r) => r.id === mine);
  assert.equal(m.included_in.reference, record.report.reference);
  assert.match(quarantine.autoReportBlocker(m), /sent to the NCA with/);
  assert.equal(all.find((r) => r.id === theirs).included_in, undefined);
  await assert.rejects(quarantine.deleteUnreported(mine, "x", "admin:1"), /kept for one year/);
});

test("NCA: a later match from the same uploader goes in a supplementary report, without repeating the file", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const user = "100000000000000001";
  const csam = await quarantine.put({ detection: detection({ category: "csam", user_id: user }), content: GIF, fileName: "a.gif", subject: { user_id: user } });
  const { calls, fetchImpl } = typedFetch(okN);
  const { record } = await quarantine.submitToNca(csam, "system:auto-report", { ...NCA, fetchImpl });
  await assert.rejects(quarantine.submitSupplementary(csam, "system:auto-report", { ...NCA, fetchImpl }), /no further matches/);
  const later = await quarantine.put({ detection: detection({ category: "harmful-abusive-material", user_id: user }), content: GIF, fileName: "b.gif", subject: { user_id: user } });
  const [summary] = (await quarantine.list("admin:1")).filter((r) => r.id === csam);
  assert.equal(quarantine.relatedMatches(summary, await quarantine.list("admin:1")).length, 1);
  await quarantine.submitSupplementary(csam, "system:auto-report", { ...NCA, fetchImpl });
  assert.deepEqual(calls[1].files.map((f) => f.name), ["quark-report.json", "other-match-1-b.gif"]);
  const lines = calls[1].submission.reportedInformation.additionalInformation.map((l) => l.value).join("\n");
  assert.match(lines, new RegExp(`Supplementary report to ${record.report.reference}.*further matches from the same uploader`));
  assert.match(lines, new RegExp(`The reported file was sent with ${record.report.reference}`));
  const [l] = (await quarantine.list("admin:1")).filter((r) => r.id === later);
  assert.ok(l.included_in);
});

// ---------------------- NCA: one incident, how it was posted, chat record

test("NCA: reports from the same server within two weeks name each other; match type and how it was posted are stated", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const put = (user, extra = {}) =>
    quarantine.put({
      detection: detection({ category: "csam", user_id: user, guild_id: "777", match_type: "near" }),
      content: GIF,
      fileName: "x.gif",
      subject: { user_id: user, guild_id: "777", channel_id: "8", message_id: "9" },
      relevantData: { posted_as: "as an ordinary message by the account", message: { id: "9", content: "" } },
      ...extra,
    });
  const a = await put("100000000000000001");
  const { calls, fetchImpl } = typedFetch(okN);
  const first = await quarantine.submitToNca(a, "system:auto-report", { ...NCA, fetchImpl });
  const b = await put("100000000000000002");
  await quarantine.submitToNca(b, "system:auto-report", { ...NCA, fetchImpl });
  const summary = calls[1].submission.reportedInformation.incidentSummary;
  assert.ok(summary.relatedPreviousReferrals.split(",").includes(first.record.report.reference));
  assert.match(summary.additionalInfo, /near-duplicate match\. Not viewed by Quark\. How it was posted: as an ordinary message by the account\./);
});

test("NCA: the chat record is attached when switched on, and can be sent alone as a supplementary report", async () => {
  const { quarantine } = storeAt({ t: Date.parse("2026-11-05T10:05:00Z") });
  const id = await quarantine.put({
    detection: detection({ category: "csam", user_id: "100000000000000001" }),
    content: GIF,
    fileName: "x.gif",
    subject: { user_id: "100000000000000001", username: "someone" },
    relevantData: {
      message: { id: "9", channel_id: "8", created_at: "2026-11-05T10:00:00Z", content: "", attachments: [{ name: "x.gif", size: 47 }] },
      posted_as: "as an ordinary message by the account",
      cached_messages: {
        messages: [{ id: "5", channel_id: "8", created_at: "2026-11-04T10:00:00Z", content: "hello there" }],
        messages_to_user: [{ id: "6", author_id: "200000000000000002", channel_id: "8", created_at: "2026-11-04T11:00:00Z", content: "hi <@100000000000000001>", reply_to: "5" }],
      },
    },
  });
  const { calls, fetchImpl } = typedFetch(okN);
  await quarantine.submitToNca(id, "system:auto-report", { ...NCA, fetchImpl });
  assert.deepEqual(calls[0].files.map((f) => f.name), ["x.gif", "quark-report.json"]);
  await assert.rejects(quarantine.submitSupplementary(id, "admin:1", { ...NCA, fetchImpl }), /Nothing to supplement/);
  await quarantine.submitSupplementary(id, "admin:1", { ...NCA, fetchImpl }, {}, { chatDocument: true });
  assert.deepEqual(calls[1].files.map((f) => [f.name, f.type]), [[`chat-log-${id}.txt`, "text/plain"], ["quark-report.json", "application/json"]]);
  const lines = calls[1].submission.reportedInformation.additionalInformation.map((l) => l.value).join("\n");
  assert.match(lines, /the chat record Quark holds for SR-CSEAIRP-\d+, as a readable document/);
  assert.match(lines, /The reported file was sent with SR-CSEAIRP-\d+ and is not repeated here/);

  const id2 = await quarantine.put({ detection: detection({ category: "csam" }), content: GIF, fileName: "y.gif", subject: {} });
  await quarantine.submitToNca(id2, "system:auto-report", { ...NCA, chatDocument: "txt", fetchImpl });
  assert.deepEqual(calls[2].files.map((f) => f.name), ["y.gif", `chat-log-${id2}.txt`, "quark-report.json"]);
});

test("NCA: the chat record reads as a document, with no links", async () => {
  const { chatDocument } = await import("../dist/src/quarantine/nca.js");
  const text = chatDocument(
    { id: "abc", report: { reference: "SR-CSEAIRP-9" } },
    {
      "3_user": { username: "someone", discord_user_id: "1" },
      "6_when_and_where": { discord_server_id: "777", discord_server_name: "Srv", discord_channel_id: "8", discord_message_id: "9" },
      "7_relevant_data_two_weeks": {
        at_match: {
          message: { id: "9", channel_id: "8", created_at: "2026-11-05T10:00:00Z", content: "", attachments: [{ name: "x.gif", size: 47 }] },
          posted_as: "as an ordinary message by the account",
          cached_messages: { messages: [], messages_to_user: [{ id: "6", author_id: "2", channel_id: "8", created_at: "2026-11-04T11:00:00Z", content: "hi", reply_to: "5" }] },
        },
        added_since: { website: { logs: { ok: false, error: "archive down" }, moderation_cases: { ok: true, rows: [] } } },
      },
    },
  );
  assert.match(text, /NCA reference: SR-CSEAIRP-9/);
  assert.match(text, /\[2026-11-05 10:00:00 UTC\] someone \(1\) in channel 8 \(message 9\):\n    \(no text\)\n    \[attachment: x\.gif, 47 bytes\]\n    Posted as an ordinary message by the account\./);
  assert.match(text, /2\. THE USER'S OTHER MESSAGES.*\(0\)[\s\S]*None held\./);
  assert.match(text, /\[2026-11-04 11:00:00 UTC\] 2 in channel 8 \(message 6\), replying to message 5:\n    hi/);
  assert.match(text, /Log archive: could not be read \(archive down\)\./);
  assert.doesNotMatch(text, /https?:/);
});

// ------------------------------ NCA: the channel around the file (±15 min)

test("NCA: a match waits for the channel's messages around it, then reports with them", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: GIF, fileName: "x.gif", subject: {} });
  await quarantine.expectChannelContext(id, "2026-11-05T10:15:00.000Z", "system:bot");
  await quarantine.expectChannelContext(id, "2026-11-05T10:12:00.000Z", "system:bot"); // never moved earlier
  let [rec] = await quarantine.list("admin:1");
  assert.equal(quarantine.autoReportBlocker(rec), "waiting for the channel's messages around it (until 10:15 UTC)");

  // A partial capture at the match does not end the wait.
  await quarantine.addRelevantData(id, "channel-context", { complete: false, messages: [] }, "system:bot");
  [rec] = await quarantine.list("admin:1");
  assert.match(quarantine.autoReportBlocker(rec), /^waiting/);

  // Extended by a later match in the same channel.
  await quarantine.expectChannelContext(id, "2026-11-05T10:25:00.000Z", "system:bot");
  clock.t = Date.parse("2026-11-05T10:20:00Z");
  await quarantine.addRelevantData(
    id,
    "channel-context",
    {
      complete: true,
      channel_id: "8",
      from: "2026-11-05T09:45:00.000Z",
      to: "2026-11-05T10:25:00.000Z",
      extended: true,
      messages: [{ id: "1", author_id: "2", channel_id: "8", created_at: "2026-11-05T09:58:00Z", content: "anyone got more" }],
    },
    "system:bot",
  );
  [rec] = await quarantine.list("admin:1");
  assert.equal(rec.channel_context.messages, 1);
  assert.equal(quarantine.autoReportBlocker(rec), null);

  const { chatDocument } = await import("../dist/src/quarantine/nca.js");
  const fields = await quarantine.reportFields(id, "admin:1");
  const text = chatDocument({ id }, fields);
  assert.match(text, /5\. THE CHANNEL AROUND THE FILE, ALL USERS[\s\S]*2026-11-05 09:45:00 UTC to 2026-11-05 10:25:00 UTC \(extended: further matches followed in this channel\)\. 1 message\(s\)\.\n\[2026-11-05 09:58:00 UTC\] 2 in channel 8 \(message 1\):\n    anyone got more/);
});

test("NCA: if the channel's messages never arrive, the report goes 10 minutes after the window", async () => {
  const clock = { t: Date.parse("2026-11-05T10:00:00Z") };
  const { quarantine } = storeAt(clock);
  const id = await quarantine.put({ detection: detection({ category: "csam" }), content: GIF, fileName: "x.gif", subject: {} });
  await quarantine.expectChannelContext(id, "2026-11-05T10:15:00.000Z", "system:bot");
  clock.t = Date.parse("2026-11-05T10:24:59Z");
  let [rec] = await quarantine.list("admin:1");
  assert.match(quarantine.autoReportBlocker(rec), /^waiting/);
  clock.t = Date.parse("2026-11-05T10:25:01Z");
  [rec] = await quarantine.list("admin:1");
  assert.equal(quarantine.autoReportBlocker(rec), null);
});
