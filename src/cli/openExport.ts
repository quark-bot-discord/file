#!/usr/bin/env node
/**
 * Open a file exported from the quarantine for an NCA report.
 *
 * The admin page hands over the file sealed under a one-off key, and shows
 * the key once. Run this on the machine the report is submitted from, then
 * upload the output to the NCA portal and delete both copies.
 *
 *   node node_modules/file/dist/src/cli/openExport.js \
 *     <quarantine-<id>.bin> <one-off key> <output path>
 *
 * Do not open the output.
 */
import { readFileSync, writeFileSync } from "fs";
import { basename } from "path";
import { openExport } from "../quarantine/index.js";

const [input, key, output] = process.argv.slice(2);
if (!input || !key || !output) {
  console.error("Usage: openExport.js <file.bin> <key> <output>");
  process.exit(2);
}
const plain = openExport(readFileSync(input), key, basename(input));
writeFileSync(output, plain, { mode: 0o600 });
console.log(`Wrote ${plain.length} bytes to ${output}. Do not open it.`);
