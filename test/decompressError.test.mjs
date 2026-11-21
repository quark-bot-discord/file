// A stored file whose bytes are not valid zstd must fail the read, never the
// process: nobody may be listening when the decompressor gives up.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { fetchFile } from "../dist/src/core/fetchFile.js";

test("an undecodable file fails its reader without an uncaught exception", async () => {
  const key = randomBytes(32);
  const iv = randomBytes(16);
  // 0x28 is neither the Brotli (0x01) nor the none (0x00) indicator, so it is
  // read as zstd - and is not zstd.
  const plain = Buffer.concat([Buffer.from([0x28]), randomBytes(4096)]);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);

  let uncaught = null;
  const onUncaught = (error) => (uncaught = error);
  process.on("uncaughtException", onUncaught);
  try {
    const stream = fetchFile(Readable.from([enc]), key, iv);
    // Nobody reads it for a while, as when serverlog holds it for a send.
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(uncaught, null);
    await assert.rejects(
      (async () => {
        for await (const _ of stream) void _;
      })(),
    );
  } finally {
    process.removeListener("uncaughtException", onUncaught);
  }
});
