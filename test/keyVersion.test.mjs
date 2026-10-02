/**
 * Round trip through downloadFile -> stored bytes -> fetchFile, for both key
 * derivations. S3 is replaced by an in-memory map; the download, compression
 * and encryption are the real code.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { randomBytes } from "node:crypto";
import { Readable, Writable } from "node:stream";
import { S3Client } from "@aws-sdk/client-s3";

// The constructor sends a lifecycle rule to the bucket; there is no bucket here.
S3Client.prototype.send = async () => ({});

const { default: FileStorage } = await import("../dist/src/index.js");

const original = randomBytes(300_000);
let server;
let url;

before(async () => {
  server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/octet-stream");
    res.end(original);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  url = `http://127.0.0.1:${server.address().port}/attachments/2/3/file.bin`;
});

after(() => server.close());

/** A FileStorage whose uploads and reads go to `store` instead of S3. */
function storage(store, encryptionSecret) {
  const fs = new FileStorage({
    s3Url: "http://s3.invalid/",
    s3FileBucket: "files",
    s3AccessKeyId: "x",
    s3SecretAccessKey: "y",
    s3Region: "r",
    encryptionSecret,
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
  return fs;
}

async function read(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

const ids = ["1", "2", "3", original.length];
const save = (fs, key = null, extended = false) =>
  fs.downloadFile(url, ids[0], ids[1], ids[2], 0, ids[3], false, key, extended);
const load = (fs, key = null, extended = false) =>
  fs.fetchFile(ids[0], ids[1], ids[2], ids[3], false, key, extended);

test("no secret: version 1, no metadata, round trips", async () => {
  delete process.env.FILE_ENCRYPTION_SECRET;
  const store = new Map();
  const fs = storage(store);
  await save(fs);
  const [object] = [...store.values()];
  assert.equal(object.Metadata, undefined);
  assert.deepEqual(await read((await load(fs)).stream), original);
});

test("secret: version 2 is marked, round trips, and differs from version 1", async () => {
  const v1 = new Map();
  await save(storage(v1));
  const v2 = new Map();
  const fs = storage(v2, "secret-a");
  await save(fs);
  const [name] = [...v2.keys()];
  assert.deepEqual(v2.get(name).Metadata, { kv: "2" });
  assert.equal([...v1.keys()][0], name, "object name must not change");
  assert.notDeepEqual(v2.get(name).body, v1.get(name).body);
  assert.deepEqual(await read((await load(fs)).stream), original);
});

test("secret holder still reads a version 1 object", async () => {
  const store = new Map();
  await save(storage(store));
  const fs = storage(store, "secret-a");
  assert.deepEqual(await read((await load(fs)).stream), original);
});

test("version 2 object without the secret is refused, not garbled", async () => {
  const store = new Map();
  await save(storage(store, "secret-a"));
  await assert.rejects(load(storage(store)), /FILE_ENCRYPTION_SECRET/);
});

test("version 2 object with the wrong secret does not yield the file", async () => {
  const store = new Map();
  await save(storage(store, "secret-a"));
  let result;
  try {
    result = await read((await load(storage(store, "secret-b"))).stream);
  } catch {
    return; // decrypt or decompress failed, as expected
  }
  assert.notDeepEqual(result, original);
});

test("env var is the fallback for the option", async () => {
  process.env.FILE_ENCRYPTION_SECRET = "from-env";
  const store = new Map();
  await save(storage(store));
  assert.deepEqual([...store.values()][0].Metadata, { kv: "2" });
  delete process.env.FILE_ENCRYPTION_SECRET;
});

test("keyed objects (assets) stay on version 1 even with a secret", async () => {
  const store = new Map();
  const fs = storage(store, "secret-a");
  await save(fs, "mavatar", true);
  assert.equal([...store.values()][0].Metadata, undefined);
  // asset-storage-node hands out keys with the 4-argument call:
  const legacy = fs.getEncryptionKeys(ids[0], ids[1], ids[2], ids[3]);
  const plain = storage(new Map()).getEncryptionKeys(
    ids[0],
    ids[1],
    ids[2],
    ids[3],
  );
  assert.deepEqual(legacy, plain);
  assert.deepEqual(
    await read((await load(fs, "mavatar", true)).stream),
    original,
  );
});
