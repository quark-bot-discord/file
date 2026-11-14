/**
 * The NCA's server sends its certificate without the intermediate. The
 * report must still go, with verification on: the intermediate is fetched
 * from the certificate's CA Issuers address, and only if it really issued it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import { submitReferral, intermediateFor } from "../dist/src/quarantine/nca.js";

const listen = (server) => new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));

function makeChain(aiaPort, issuerName = "int") {
  const dir = mkdtempSync(join(tmpdir(), "nca-chain-"));
  const run = (...args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  writeFileSync(join(dir, "ext.cnf"), `[ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n[leaf_ext]\nbasicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nauthorityInfoAccess=caIssuers;URI:http://127.0.0.1:${aiaPort}/${issuerName}.cer\n`);
  run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem", "-subj", "/CN=Test Root", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  for (const name of ["int", "other"]) {
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=Test ${name}`);
    run("x509", "-req", "-in", `${name}.csr`, "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", `${name}.pem`, "-days", "2", "-extfile", "ext.cnf", "-extensions", "ca_ext");
    run("x509", "-in", `${name}.pem`, "-outform", "der", "-out", `${name}.cer`);
  }
  run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost");
  run("x509", "-req", "-in", "leaf.csr", "-CA", "int.pem", "-CAkey", "int.key", "-CAcreateserial", "-out", "leaf.pem", "-days", "2", "-extfile", "ext.cnf", "-extensions", "leaf_ext");
  const read = (f) => readFileSync(join(dir, f));
  return { root: read("root.pem").toString(), leaf: read("leaf.pem"), leafKey: read("leaf.key"), cer: { int: read("int.cer"), other: read("other.cer") } };
}

async function setUp(issuerName) {
  const aia = http.createServer();
  const aiaPort = await listen(aia);
  const chain = makeChain(aiaPort, issuerName);
  aia.on("request", (req, res) => res.end(chain.cer[req.url.slice(1, -4)] ?? ""));
  const received = [];
  // Sends its own certificate only, like the NCA's server.
  const api = https.createServer({ cert: chain.leaf, key: chain.leafKey }, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ url: req.url, key: req.headers["x-api-key"], org: req.headers.orgid, type: req.headers["content-type"], body });
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ referralID: "r-1", referralFriendlyID: "SR-CSEAIRP-1" }));
    });
  });
  const apiPort = await listen(api);
  const config = {
    apiKey: "k", orgId: "o", baseUrl: `https://localhost:${apiPort}/submission`, espName: "Quark",
    reporter: { firstName: "a", lastName: "b", email: "c@d", phone: "", phoneCountryCode: "+44" },
    rootCertificates: [chain.root],
  };
  return { config, received, close: () => { aia.close(); api.close(); }, apiPort };
}

test("an incomplete chain: the intermediate is fetched and the report is sent, verified", async () => {
  const { config, received, close } = await setUp("int");
  try {
    const result = await submitReferral(config, { hello: 1 }, [{ name: "quark-report.json", type: "application/json", bytes: Buffer.from("{}") }]);
    assert.equal(result.referralFriendlyID, "SR-CSEAIRP-1");
    assert.equal(received.length, 1);
    assert.equal(received[0].url, "/submission/api/referral/");
    assert.equal(received[0].key, "k");
    assert.equal(received[0].org, "o");
    assert.match(received[0].type, /^multipart\/form-data; boundary=/);
    assert.match(received[0].body, /name="submission"/);
    assert.match(received[0].body, /filename="quark-report.json"/);
  } finally {
    close();
  }
});

test("a certificate at the CA Issuers address that did not issue the server's is refused", async () => {
  const { close, apiPort } = await setUp("other");
  try {
    await assert.rejects(intermediateFor("localhost", apiPort), /is not the certificate that issued/);
  } finally {
    close();
  }
});

test("without the intermediate's root trusted, it still fails: verification stays on", async () => {
  const { config, close } = await setUp("int");
  try {
    await assert.rejects(submitReferral({ ...config, rootCertificates: [] }, {}, []), (e) => /certificate|issuer/i.test(e.message ?? e.code ?? ""));
  } finally {
    close();
  }
});
