/**
 * The illegal-content check: local hashing, the Arachnid Shield client, and
 * what downloadFile and fetchFile do with each outcome. S3 is an in-memory
 * map and the matcher is a local HTTP server; the hashing, download,
 * compression and encryption are the real code.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { randomBytes } from "node:crypto";
import { crc32 } from "node:zlib";
import { Readable, Writable } from "node:stream";
import sharp from "sharp";
import { S3Client } from "@aws-sdk/client-s3";

// Everything sent to S3 directly (lifecycle rule, marker objects) lands here.
const sent = [];
S3Client.prototype.send = async (command) => {
  sent.push(command);
  return {};
};

const {
  default: FileStorage,
  FileWithheld,
  Scanner,
  ArachnidShieldMatcher,
  scannerFromEnv,
} = await import("../dist/src/index.js");
const { pdqHash, HasherUnavailable, TooManyPixels } = await import(
  "../dist/src/scan/index.js"
);
const { isHashableImage } = await import("../dist/src/scan/sniff.js");

/** The same picture the reference hashes below were computed from. */
function pixels(w, h, k) {
  const data = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y++) {
    const by = Math.floor((y * 12) / h);
    for (let x = 0; x < w; x++) {
      const bx = Math.floor((x * 16) / w);
      const i = (y * w + x) * 3;
      data[i] = (bx * 37 * k + by * 91) % 256;
      data[i + 1] = (Math.floor((x * 255) / w) + by * k * 7) % 256;
      data[i + 2] = ((bx ^ by) * 31 * k + Math.floor((y * 255) / h)) % 256;
    }
  }
  return sharp(data, { raw: { width: w, height: h, channels: 3 } });
}
const png = (w, h, k) => pixels(w, h, k).png().toBuffer();

/**
 * Hashes of the pictures above from `pdqhash` 0.2 (the Python binding to
 * Meta's reference C++ implementation), computed on the raw pixels.
 */
const REFERENCE = [
  [
    640,
    480,
    1,
    "4f0ffee4a513e6f0ea0e98cfdee8c21af0f06e00ab5caa254af0d4a6756ae052",
  ],
  [
    300,
    700,
    2,
    "54abda194f4d72a1edabcc5eb0f221e7ab556200ce8a61b2c72a7e4acf5256c4",
  ],
  [
    1920,
    1080,
    3,
    "ca6fab803555e6009bdb19fbcaba5c7f35b0e825356ee80f0358e9122356ee50",
  ],
];
const LARGE = [
  4000,
  3000,
  5,
  "bf70ca15b8dab6c1eaabc13ee725b1eac08fc6486ddac643b29abc5488b06e60",
];

function distance(a, b) {
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    while (x) {
      bits += x & 1;
      x >>= 1;
    }
  }
  return bits;
}

async function read(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------- hashing

test("PDQ hash equals the reference implementation's, bit for bit", async () => {
  for (const [w, h, k, expected] of REFERENCE) {
    const { hash, quality } = await pdqHash(await png(w, h, k));
    assert.equal(hash.toString("hex"), expected, `${w}x${h}`);
    assert.equal(quality, 100);
  }
});

test("an image over the full-size limit is shrunk and still lands within match distance", async () => {
  const [w, h, k, expected] = LARGE;
  const { hash } = await pdqHash(await png(w, h, k));
  const bits = distance(hash, Buffer.from(expected, "hex"));
  assert.ok(bits <= 16, `distance ${bits}`);
});

test("JPEG, WebP and GIF encodings of a picture hash within match distance of it", async () => {
  const [w, h, k, expected] = REFERENCE[0];
  const reference = Buffer.from(expected, "hex");
  for (const [name, buffer] of [
    ["jpeg", await pixels(w, h, k).jpeg({ quality: 80 }).toBuffer()],
    ["webp", await pixels(w, h, k).webp({ quality: 80 }).toBuffer()],
    ["gif", await pixels(w, h, k).gif().toBuffer()],
  ]) {
    assert.ok(isHashableImage(buffer), name);
    const bits = distance((await pdqHash(buffer)).hash, reference);
    assert.ok(bits <= 31, `${name}: distance ${bits}`);
  }
});

test("only image content is treated as an image, whatever it is called", () => {
  assert.equal(
    isHashableImage(Buffer.from("%PDF-1.7 not an image at all")),
    false,
  );
  assert.equal(isHashableImage(randomBytes(4)), false);
  assert.equal(isHashableImage(Buffer.from("RIFF\0\0\0\0WAVEfmt ")), false);
  assert.equal(isHashableImage(Buffer.from("RIFF\0\0\0\0WEBPVP8 ")), true);
});

// ------------------------------------------------- matcher (fake service)

let shield;
let shieldUrl;
const shieldRequests = [];
/** hash (base64) -> classification; anything else is no-known-match */
const known = new Map();
let shieldMode = "ok";

let files;
let filesUrl;
const served = new Map();

before(async () => {
  shield = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      shieldRequests.push({
        url: req.url,
        method: req.method,
        authorization: req.headers.authorization,
        body: JSON.parse(body),
      });
      if (shieldMode === "down") {
        res.statusCode = 503;
        return res.end("{}");
      }
      const scanned_hashes = {};
      for (const hash of JSON.parse(body).hashes) {
        if (shieldMode === "omit") continue;
        const classification = known.get(hash);
        scanned_hashes[hash] = classification
          ? {
              classification,
              match_type: "near",
              // The spec's shape: a list of NearMatchDetail.
              near_match_details: [
                {
                  sha1_base32: "X",
                  sha256_hex: "ABC123",
                  classification,
                  timestamp: 0,
                },
              ],
            }
          : {
              classification: "no-known-match",
              match_type: null,
              near_match_details: [],
            };
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ scanned_hashes }));
    });
  });
  await new Promise((resolve) => shield.listen(0, "127.0.0.1", resolve));
  shieldUrl = `http://127.0.0.1:${shield.address().port}/`;

  files = http.createServer((req, res) => {
    const file = served.get(req.url);
    res.setHeader("content-type", "application/octet-stream");
    res.end(file);
  });
  await new Promise((resolve) => files.listen(0, "127.0.0.1", resolve));
  filesUrl = `http://127.0.0.1:${files.address().port}`;
});

after(() => {
  shield.close();
  files.close();
});

const matcher = () =>
  new ArachnidShieldMatcher({
    username: "user",
    password: "pass",
    baseUrl: shieldUrl,
  });

test("the matcher sends hashes only, batched, with basic auth", async () => {
  shieldRequests.length = 0;
  shieldMode = "ok";
  const m = matcher();
  const a = Buffer.alloc(32, 1);
  const b = Buffer.alloc(32, 2);
  known.set(b.toString("base64"), "csam");
  const [ra, rb, ra2] = await Promise.all([
    m.lookup(a),
    m.lookup(b),
    m.lookup(a),
  ]);

  assert.equal(ra, null);
  assert.equal(ra2, null);
  assert.deepEqual(rb, {
    category: "csam",
    matchType: "near",
    reference: "ABC123",
    // The service's answer as given: kept as the basis for a report.
    details: {
      classification: "csam",
      match_type: "near",
      near_match_details: [
        {
          sha1_base32: "X",
          sha256_hex: "ABC123",
          classification: "csam",
          timestamp: 0,
        },
      ],
    },
  });
  assert.equal(shieldRequests.length, 1);
  const [request] = shieldRequests;
  assert.equal(request.method, "POST");
  assert.equal(request.url, "/v1/pdq");
  assert.equal(
    request.authorization,
    "Basic " + Buffer.from("user:pass").toString("base64"),
  );
  assert.deepEqual(request.body, {
    hashes: [a.toString("base64"), b.toString("base64")],
  });
});

test("an unreachable matcher, or one that skips a hash, is an error and never a pass", async () => {
  const m = matcher();
  shieldMode = "down";
  await assert.rejects(m.lookup(Buffer.alloc(32, 3)), /503/);
  shieldMode = "omit";
  await assert.rejects(m.lookup(Buffer.alloc(32, 3)), /no result/);
  shieldMode = "ok";
});

// ------------------------------------------- storage (in-memory S3)

/** A FileStorage whose uploads and reads go to `store` instead of S3. */
function storage(store, scannerOptions) {
  const detections = [];
  const fs = new FileStorage({
    s3Url: "http://s3.invalid/",
    s3FileBucket: "files",
    s3AccessKeyId: "x",
    s3SecretAccessKey: "y",
    s3Region: "r",
    scanner:
      scannerOptions === null
        ? null
        : new Scanner({
            matcher: matcher(),
            onDetection: (d) => detections.push(d),
            ...scannerOptions,
          }),
  });
  fs.uploadStream = ({ Key, Metadata }) => {
    const chunks = [];
    let done;
    const promise = new Promise((resolve) => (done = resolve));
    const writeStream = new Writable({
      write(chunk, _enc, cb) {
        chunks.push(chunk);
        cb();
      },
      final(cb) {
        store.set(Key, { body: Buffer.concat(chunks), Metadata });
        cb();
        done();
      },
    });
    return { writeStream, promise };
  };
  fs.fetchFileRaw = async (_bucket, Key) => {
    const object = store.get(Key);
    if (!object) throw new Error("NoSuchKey");
    return {
      Body: Readable.from([object.body]),
      ContentLength: object.body.length,
      Metadata: object.Metadata,
    };
  };
  // Marker objects are written with a plain PutObject and looked for with a
  // HeadObject.
  fs.s3Files.send = async (command) => {
    if (command.constructor.name === "PutObjectCommand") {
      store.set(command.input.Key, {
        body: Buffer.from(command.input.Body),
        Metadata: command.input.Metadata,
      });
    }
    if (command.constructor.name === "HeadObjectCommand") {
      const object = store.get(command.input.Key);
      if (!object)
        throw Object.assign(new Error("NotFound"), { name: "NotFound" });
      return { Metadata: object.Metadata };
    }
    return {};
  };
  return { fs, detections };
}

let nextId = 100;
/** Serve `file` and return the arguments downloadFile and fetchFile take for it. */
function attachment(file) {
  const id = String(nextId++);
  served.set(`/attachments/2/${id}/upload`, file);
  return {
    id,
    download: [
      `${filesUrl}/attachments/2/${id}/upload`,
      "1",
      "2",
      id,
      0,
      file.length,
      false,
    ],
    fetch: ["1", "2", id, file.length, false],
  };
}
const withContext = (args) => [
  ...args,
  null,
  false,
  { message_id: "555", user_id: "777" },
];

test("a clear image is stored, marked clear, and comes back byte for byte", async () => {
  const store = new Map();
  const { fs, detections } = storage(store);
  const file = await png(640, 480, 7);
  const a = attachment(file);

  await fs.downloadFile(...a.download);
  const [object] = [...store.values()];
  assert.deepEqual(object.Metadata, { scan: "clear" });

  const fetched = await fs.fetchFile(...a.fetch);
  assert.deepEqual(await read(fetched.stream), file);
  assert.equal(detections.length, 0);
});

test("a file that is not an image is stored and returned untouched, and nothing is sent to the matcher", async () => {
  shieldRequests.length = 0;
  const store = new Map();
  const { fs } = storage(store);
  const file = randomBytes(300_000);
  const a = attachment(file);

  await fs.downloadFile(...a.download);
  assert.equal([...store.values()][0].Metadata, undefined);
  const fetched = await fs.fetchFile(...a.fetch);
  assert.deepEqual(await read(fetched.stream), file);
  assert.equal(shieldRequests.length, 0);
});

test("a match at download is never stored: a marker is left, it is reported, and fetch refuses", async () => {
  const store = new Map();
  const { fs, detections } = storage(store);
  const file = await png(640, 480, 11);
  const hash = (await pdqHash(file)).hash.toString("base64");
  known.set(hash, "csam");
  const a = attachment(file);

  await assert.rejects(fs.downloadFile(...withContext(a.download)), (error) => {
    assert.ok(error instanceof FileWithheld);
    assert.equal(error.reason, "csam");
    assert.equal(error.stage, "store");
    return true;
  });

  const objects = [...store.values()];
  assert.equal(objects.length, 1);
  assert.equal(objects[0].body.length, 0, "no file bytes stored");
  assert.deepEqual(objects[0].Metadata, { withheld: "csam" });

  assert.equal(detections.length, 1);
  const [d] = detections;
  assert.equal(d.stage, "store");
  assert.equal(d.category, "csam");
  assert.equal(d.pdq, hash);
  assert.equal(d.reference, "ABC123");
  assert.equal(d.attachment_id, a.id);
  assert.deepEqual(d.context, { message_id: "555", user_id: "777" });
  assert.ok(!JSON.stringify(d).includes(filesUrl), "no link to the file");

  await assert.rejects(fs.fetchFile(...a.fetch), (error) => {
    assert.ok(error instanceof FileWithheld);
    assert.equal(error.reason, "csam");
    return true;
  });
  // The marker is honoured by a process that has no scanner at all.
  const { fs: plain } = storage(store, null);
  await assert.rejects(plain.fetchFile(...a.fetch), FileWithheld);
  // Downloaded again (an edit): withheld again, reported once.
  await assert.rejects(fs.downloadFile(...a.download), FileWithheld);
  assert.equal(detections.length, 1);

  // Downloaded again by a process that cannot check it (fresh scanner, so no
  // cached answer, and the matcher is down): the marker must survive.
  shieldMode = "down";
  await assert.rejects(
    storage(store).fs.downloadFile(...a.download),
    (error) => {
      assert.ok(error instanceof FileWithheld);
      assert.equal(error.reason, "csam");
      return true;
    },
  );
  shieldMode = "ok";
  assert.equal(store.size, 1);
  assert.equal(
    [...store.values()][0].body.length,
    0,
    "still no file bytes stored",
  );
});

test("a file stored clear that matches later is withheld at re-upload and reported", async () => {
  const store = new Map();
  const { fs: storing } = storage(store);
  const file = await png(640, 480, 13);
  const a = attachment(file);
  await storing.downloadFile(...a.download);

  // The database learns about it afterwards. A fresh scanner has no cache.
  known.set(
    (await pdqHash(file)).hash.toString("base64"),
    "harmful-abusive-material",
  );
  const { fs, detections } = storage(store);
  await assert.rejects(fs.fetchFile(...withContext(a.fetch)), (error) => {
    assert.ok(error instanceof FileWithheld);
    assert.equal(error.reason, "harmful-abusive-material");
    assert.equal(error.stage, "reupload");
    return true;
  });
  assert.equal(detections.length, 1);
  assert.equal(detections[0].stage, "reupload");
  assert.equal(detections[0].context.user_id, "777");
});

test("matcher down at download: the file is stored without a clear mark", async () => {
  const store = new Map();
  const { fs } = storage(store);
  const file = await png(640, 480, 17);
  const a = attachment(file);
  shieldMode = "down";
  await fs.downloadFile(...a.download);
  shieldMode = "ok";
  assert.equal([...store.values()][0].Metadata, undefined);
});

test("matcher down at re-upload: withheld as unchecked unless it passed when stored", async () => {
  const store = new Map();
  const file = await png(640, 480, 19);

  // Stored while the matcher was down, so never checked.
  const unchecked = attachment(file);
  shieldMode = "down";
  await storage(store).fs.downloadFile(...unchecked.download);
  await assert.rejects(
    storage(store).fs.fetchFile(...unchecked.fetch),
    (error) => {
      assert.ok(error instanceof FileWithheld);
      assert.equal(error.reason, "unchecked");
      return true;
    },
  );
  // The same situation with failClosed off lets it through.
  const open = await storage(store, { failClosed: false }).fs.fetchFile(
    ...unchecked.fetch,
  );
  assert.deepEqual(await read(open.stream), file);

  // Stored while the matcher was up, so it has a clear mark.
  shieldMode = "ok";
  const checked = attachment(file);
  await storage(store).fs.downloadFile(...checked.download);
  shieldMode = "down";
  const fetched = await storage(store).fs.fetchFile(...checked.fetch);
  assert.deepEqual(await read(fetched.stream), file);
  shieldMode = "ok";
});

test("an image that cannot be checked is stored unmarked and withheld at re-upload", async () => {
  const file = await png(640, 480, 23);
  const cases = {
    "over the size limit": { maxBytes: 1000 },
    "hasher unavailable": {
      hasher: async () => {
        throw new HasherUnavailable("no sharp");
      },
    },
    "too many pixels": {
      hasher: async () => {
        throw new TooManyPixels("gif 20000x20000");
      },
    },
  };
  for (const [name, options] of Object.entries(cases)) {
    shieldRequests.length = 0;
    const store = new Map();
    const { fs } = storage(store, options);
    const a = attachment(file);
    await fs.downloadFile(...a.download);
    assert.equal([...store.values()][0].Metadata, undefined, name);
    await assert.rejects(fs.fetchFile(...a.fetch), (error) => {
      assert.ok(error instanceof FileWithheld, name);
      assert.equal(error.reason, "unchecked", name);
      return true;
    });
    assert.equal(shieldRequests.length, 0, name);
    // With failClosed off it comes back whole.
    const open = await storage(store, {
      ...options,
      failClosed: false,
    }).fs.fetchFile(...a.fetch);
    assert.deepEqual(await read(open.stream), file, name);
  }
});

test("a canvas too large to decode safely is refused from its header alone", async () => {
  // A real 8x8 interlaced PNG whose header is rewritten to declare a huge canvas.
  const small = await sharp({
    create: { width: 8, height: 8, channels: 3, background: "#123456" },
  })
    .png({ progressive: true })
    .toBuffer();
  const declaring = (side) => {
    const image = Buffer.from(small);
    image.writeUInt32BE(side, 16);
    image.writeUInt32BE(side, 20);
    image.writeUInt32BE(crc32(image.subarray(12, 29)), 29);
    return image;
  };
  // 64 megapixels interlaced is over the memory budget; 400 is over any limit.
  for (const side of [8000, 20000]) {
    const started = Date.now();
    await assert.rejects(pdqHash(declaring(side)), TooManyPixels, String(side));
    assert.ok(Date.now() - started < 1000);
  }
  const scanner = new Scanner({ matcher: matcher() });
  assert.deepEqual(await scanner.check(declaring(8000)), {
    status: "error",
    reason: "too_many_pixels",
  });
});

test("a file that is not an image comes back as the very same stream, unread", async () => {
  const scanner = new Scanner({ matcher: matcher() });
  const file = randomBytes(5000);
  // One byte at a time, so the header arrives across many chunks.
  const source = Readable.from(
    [...file].map((byte) => Buffer.from([byte])),
    { objectMode: false },
  );
  const { verdict, stream } = await scanner.scanStream(
    source,
    file.length,
    "reupload",
  );
  assert.deepEqual(verdict, { status: "skipped", reason: "not_image" });
  assert.equal(stream, source);
  assert.deepEqual(await read(stream), file);

  for (const tiny of [Buffer.alloc(0), Buffer.from("abc")]) {
    const result = await scanner.scanStream(
      Readable.from(tiny.length ? [tiny] : [], { objectMode: false }),
      tiny.length,
      "reupload",
    );
    assert.equal(result.verdict.status, "skipped");
    assert.deepEqual(await read(result.stream), tiny);
  }
});

test("a stalled read gives up its turn instead of blocking every later check", async () => {
  const file = await png(640, 480, 31);
  const scanner = new Scanner({
    matcher: matcher(),
    concurrency: 1,
    readTimeoutMs: 100,
  });
  // Sends the start of an image and then nothing, for ever.
  const stalled = new Readable({ read() {} });
  stalled.push(file.subarray(0, 64));
  await assert.rejects(
    scanner.scanStream(stalled, file.length, "store"),
    /Timed out/,
  );
  assert.equal(stalled.destroyed, true);

  const next = await scanner.scanStream(
    Readable.from([file], { objectMode: false }),
    file.length,
    "store",
  );
  assert.equal(next.verdict.status, "clear");
});

test("a new upload does not wait for a turn that is not coming; a re-upload waits, but not for ever", async () => {
  const file = await png(640, 480, 37);
  let release;
  const held = new Promise((resolve) => (release = resolve));
  const scanner = new Scanner({
    matcher: { name: "slow", lookup: () => held.then(() => null) },
    concurrency: 1,
    maxWaiting: 0,
    maxWaitMs: 100,
  });
  const image = () => Readable.from([file], { objectMode: false });
  const first = scanner.scanStream(image(), file.length, "store");
  await new Promise((resolve) => setTimeout(resolve, 50));

  const second = image();
  const busy = await scanner.scanStream(second, file.length, "store");
  assert.deepEqual(busy.verdict, { status: "error", reason: "busy" });
  assert.equal(busy.stream, second);
  assert.deepEqual(await read(busy.stream), file);

  const waited = await scanner.scanStream(image(), file.length, "reupload");
  assert.deepEqual(waited.verdict, { status: "error", reason: "busy" });

  release();
  assert.equal((await first).verdict.status, "clear");
  // The turn was given back.
  assert.equal(
    (await scanner.scanStream(image(), file.length, "store")).verdict.status,
    "clear",
  );
});

test("with no scanner nothing changes", async () => {
  const store = new Map();
  const { fs } = storage(store, null);
  assert.equal(fs.scanner, undefined);
  const file = await png(640, 480, 11); // the one the matcher knows as csam
  const a = attachment(file);
  await fs.downloadFile(...a.download);
  assert.equal([...store.values()][0].Metadata, undefined);
  assert.deepEqual(await read((await fs.fetchFile(...a.fetch)).stream), file);
});

test("scannerFromEnv is off without credentials and on with them", () => {
  assert.equal(scannerFromEnv({}), undefined);
  assert.equal(scannerFromEnv({ ARACHNID_SHIELD_USERNAME: "u" }), undefined);
  const scanner = scannerFromEnv({
    ARACHNID_SHIELD_USERNAME: "u",
    ARACHNID_SHIELD_PASSWORD: "p",
    FILE_SCAN_FAIL_MODE: "open",
    FILE_SCAN_ALERT_WEBHOOK: "https://discord.invalid/api/webhooks/1/x",
  });
  assert.equal(scanner.matcher.name, "arachnid-shield");
  assert.equal(scanner.failClosed, false);
  assert.equal(
    scanner.alertWebhook,
    "https://discord.invalid/api/webhooks/1/x",
  );
  assert.equal(scanner.maxBytes, 32 * 1024 * 1024);

  // A value that is not a number falls back to the default instead of
  // becoming NaN.
  const sloppy = scannerFromEnv({
    ARACHNID_SHIELD_USERNAME: "u",
    ARACHNID_SHIELD_PASSWORD: "p",
    FILE_SCAN_MAX_BYTES: "32MB",
    FILE_SCAN_CONCURRENCY: "0",
  });
  assert.equal(sloppy.maxBytes, 32 * 1024 * 1024);
  assert.equal(sloppy.concurrency, 2);
});

test("the alert carries identifiers and hashes, and no link to the file", async () => {
  const alerts = [];
  const hook = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      alerts.push(JSON.parse(body));
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise((resolve) => hook.listen(0, "127.0.0.1", resolve));
  const store = new Map();
  const { fs } = storage(store, {
    alertWebhook: `http://127.0.0.1:${hook.address().port}/hook`,
  });
  const file = await png(640, 480, 29);
  known.set((await pdqHash(file)).hash.toString("base64"), "csam");
  const a = attachment(file);
  await assert.rejects(
    fs.downloadFile(...withContext(a.download)),
    FileWithheld,
  );
  for (let i = 0; i < 50 && alerts.length === 0; i++)
    await new Promise((resolve) => setTimeout(resolve, 20));
  hook.close();

  assert.equal(alerts.length, 1);
  const { content, allowed_mentions } = alerts[0];
  assert.deepEqual(allowed_mentions, { parse: [] });
  assert.match(content, /matched `csam`/);
  assert.match(content, new RegExp(`attachment \`${a.id}\``));
  assert.match(content, /message_id `555`/);
  assert.ok(!content.includes("http"), "no link of any kind");
});

// ------------------------------------------------- quarantine from the bot

/** A quarantine stand-in that records what it is given. */
function fakeQuarantine() {
  const kept = [];
  return {
    kept,
    async put(input) {
      kept.push(input);
      return `q${kept.length}-000000000000`;
    },
  };
}

test("a match at download or re-upload puts the file and the poster's data in quarantine", async () => {
  const store = new Map();
  const quarantine = fakeQuarantine();
  const { fs } = storage(store, { quarantine });
  const file = await png(640, 480, 17);
  known.set((await pdqHash(file)).hash.toString("base64"), "csam");
  const a = attachment(file);

  const evidence = {
    subject: { user_id: "777", username: "poster", guild_id: "1", message_id: "555" },
    relevantData: () => ({ message: { content: "hello" } }),
  };
  await assert.rejects(
    fs.downloadFile(...withContext(a.download), evidence),
    FileWithheld,
  );
  // report() runs after the throw; let it finish.
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(quarantine.kept.length, 1);
  const [input] = quarantine.kept;
  assert.deepEqual(input.content, file, "the file as received");
  assert.equal(input.detection.stage, "store");
  assert.equal(input.detection.source, "bot");
  assert.equal(input.detection.user_id, "777");
  assert.equal(input.subject.username, "poster");
  assert.deepEqual(input.relevantData, { message: { content: "hello" } });

  // Stored clear, matched later: quarantined at re-upload with the decrypted file.
  const store2 = new Map();
  const file2 = await png(640, 480, 19);
  const b = attachment(file2);
  await storage(store2).fs.downloadFile(...b.download);
  known.set((await pdqHash(file2)).hash.toString("base64"), "csam");
  const quarantine2 = fakeQuarantine();
  const { fs: reading } = storage(store2, { quarantine: quarantine2 });
  await assert.rejects(reading.fetchFile(...withContext(b.fetch), evidence), FileWithheld);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(quarantine2.kept.length, 1);
  assert.deepEqual(quarantine2.kept[0].content, file2);
  assert.equal(quarantine2.kept[0].detection.stage, "reupload");
});

test("Arachnid Shield: the address in its own client, and a failed connection says why", async () => {
  const matcher = new ArachnidShieldMatcher({ username: "u", password: "p" });
  assert.equal(matcher["url"], "https://shield.projectarachnid.com/v1/pdq");

  // A port that was free a moment ago: nothing is listening on it.
  const probe = http.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  const unreachable = new ArachnidShieldMatcher({
    username: "u",
    password: "p",
    baseUrl: `http://127.0.0.1:${port}/`,
    batchWindowMs: 0,
  });
  await assert.rejects(unreachable.lookup(Buffer.alloc(32, 1)), (error) => {
    assert.equal(error.message, `could not reach 127.0.0.1:${port}: fetch failed (ECONNREFUSED)`);
    return true;
  });
});
