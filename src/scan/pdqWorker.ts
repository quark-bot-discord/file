/**
 * Runs the PDQ hash on its own thread. The hash is synchronous WebAssembly
 * and takes up to about 100 ms for a 1920x1080 image; on the main thread that
 * would stall everything else the process is doing.
 */
import { createRequire } from "module";
import { parentPort } from "worker_threads";

interface Pdq {
  init(): Promise<void>;
  hash(image: {
    data: Uint8Array;
    width: number;
    height: number;
    channels: number;
  }): { hash: Uint8Array; quality: number };
}

export interface HashRequest {
  id: number;
  pixels: ArrayBuffer;
  width: number;
  height: number;
  channels: number;
}

export type HashReply =
  | { id: number; hash: Uint8Array; quality: number }
  | { id: number; error: string; unavailable: boolean };

// pdq-wasm's ESM build cannot find its own .wasm file under Node; the
// CommonJS build can.
let ready: Promise<Pdq> | undefined;
const load = async () => {
  const { PDQ } = createRequire(import.meta.url)("pdq-wasm") as { PDQ: Pdq };
  await PDQ.init();
  return PDQ;
};

parentPort?.on("message", async (request: HashRequest) => {
  let PDQ: Pdq;
  try {
    PDQ = await (ready ??= load());
  } catch (error) {
    ready = undefined;
    const reply: HashReply = {
      id: request.id,
      error: (error as Error).message,
      unavailable: true,
    };
    return parentPort?.postMessage(reply);
  }
  try {
    const { hash, quality } = PDQ.hash({
      data: new Uint8Array(request.pixels),
      width: request.width,
      height: request.height,
      channels: request.channels,
    });
    const reply: HashReply = { id: request.id, hash, quality };
    parentPort?.postMessage(reply);
  } catch (error) {
    const reply: HashReply = {
      id: request.id,
      error: (error as Error).message,
      unavailable: false,
    };
    parentPort?.postMessage(reply);
  }
});
