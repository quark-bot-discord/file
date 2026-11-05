/**
 * Runs the PDQ hash on its own thread. The hash is synchronous WebAssembly
 * and takes up to about 100 ms for a 1920x1080 image; on the main thread that
 * would stall everything else the process is doing.
 */
import { createRequire } from "module";
import { parentPort } from "worker_threads";
// pdq-wasm's ESM build cannot find its own .wasm file under Node; the
// CommonJS build can.
let ready;
const load = async () => {
    const { PDQ } = createRequire(import.meta.url)("pdq-wasm");
    await PDQ.init();
    return PDQ;
};
parentPort?.on("message", async (request) => {
    let PDQ;
    try {
        PDQ = await (ready ?? (ready = load()));
    }
    catch (error) {
        ready = undefined;
        const reply = {
            id: request.id,
            error: error.message,
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
        const reply = { id: request.id, hash, quality };
        parentPort?.postMessage(reply);
    }
    catch (error) {
        const reply = {
            id: request.id,
            error: error.message,
            unavailable: false,
        };
        parentPort?.postMessage(reply);
    }
});
//# sourceMappingURL=pdqWorker.js.map