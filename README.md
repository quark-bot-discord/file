# file
 Downloads, compresses and encrypts files.

## Checking images against known illegal material

Off unless a matcher is configured. When on, every image is checked twice:
before it is stored (`downloadFile`) and again before it is handed back
(`fetchFile`), because the database of known material grows in between.

The file never leaves the process. A PDQ perceptual hash is computed locally
(`sharp` to decode, `pdq-wasm` to hash) and only that 32-byte hash is sent to
the matcher.

| Outcome | At `downloadFile` | At `fetchFile` |
|---|---|---|
| Match | Nothing is stored except an empty marker object. Reported. Throws `FileWithheld`. | Not returned. Reported. Throws `FileWithheld`. The stored copy is left to expire. |
| Could not be checked (matcher or hasher down, busy, image too large or undecodable) | Stored, without a "clear" mark | Throws `FileWithheld("unchecked")` unless the file was marked clear when stored. `FILE_SCAN_FAIL_MODE=open` returns it instead. |
| Clear | Stored, marked clear | Returned |
| Not an image | Stored | Returned |

`FileWithheld` has `reason` (`csam`, `harmful-abusive-material`, `unchecked`,
or whatever else the matcher classified it as) and `stage` (`store` or
`reupload`).

### What it does not catch

- Anything that is not a JPEG, PNG, GIF, WebP, TIFF or AVIF image: video,
  archives, documents.
- Any frame of an animation after the first.
- Material that is not already in the matcher's database.
- Assets (stored with a `key`) are checked when stored if the process that
  stores them is configured, but the asset readers call `fetchFileRaw`
  directly and are not checked on the way out.

### Configuration

| Variable | |
|---|---|
| `ARACHNID_SHIELD_USERNAME`, `ARACHNID_SHIELD_PASSWORD` | Turns checking on. Credentials for [Project Arachnid Shield](https://shield.projectarachnid.com/). |
| `ARACHNID_SHIELD_URL` | Other address for the service. Default `https://shield.projectarachnid.ca/`. |
| `FILE_SCAN_ALERT_WEBHOOK` | Discord webhook that gets one message per detection: identifiers and hashes, never the file or a link to it. |
| `FILE_SCAN_FAIL_MODE` | `closed` (default) or `open`. |
| `FILE_SCAN_MAX_BYTES` | Largest image read into memory to be checked. Default 33554432 (32 MiB). |
| `FILE_SCAN_CONCURRENCY` | Images decoded at once. Default 2. One decode may use up to about 150 MB. |

Set the same configuration on every process that shares a bucket. A process
with no matcher still refuses to return a marked file, but it will store over
a marker.

On start-up the scanner hashes a built-in image and makes one lookup, and logs
`[FILE SCAN] on: ...` or `[FILE SCAN] NOT WORKING ...`.

Each detection is logged as `[FILE SCAN] MATCH {json}`. Pass a `Scanner` with
`onDetection` to the constructor to record detections elsewhere. Callers can
pass a last argument to `downloadFile` and `fetchFile`, for example
`{ message_id, user_id }`, which is included in the detection.

To use another matching service, implement `Matcher` (`lookup(hash)` returning
a match or null) and pass `new Scanner({ matcher })`.
