# ftproxy: Design Spec (v0 to v2)

Private, end-to-end-encrypted, 1:1 file transfer you host yourself. Fork of
SMSproxy: same one-link model, same no-server/no-account/no-database promise.
The host runs a terminal; the guest taps one link. Either side can **offer** a
file; the other side **chooses** to accept it. Close it and the link dies.

Status: **design, not built.** Everything below is a spec to implement and test.

---

## 1. Goals / non-goals

**Goals**
- 1:1 only. One link, one guest, one seat (inherited from SMSproxy).
- Allowed types: `.txt` `.png` `.jpg/.jpeg` `.mp4` `.pdf`. Max **500 MiB** per file.
- Both directions: host → guest and guest → host.
- Consent gate: nothing is transferred until the receiver presses Accept.
- Files never touch a third party in plaintext. No storage between the endpoints.
- Integrity: a reordered, dropped, truncated, spliced, or flipped chunk is detected,
  and fails closed (tamper → burn).
- Zero runtime dependencies (Node stdlib + browser WebCrypto), like SMSproxy.

**Non-goals (v0/v1)**
- Multi-recipient, folders, persistent rooms, accounts.
- Files > 500 MiB, other file types.
- Making a valid-but-malicious PDF/MP4 safe. We verify *what type it is*, not
  *that it's harmless* (see §12).

---

## 2. Architecture (unchanged from SMSproxy)

```
 HOST machine                                             GUEST
 ┌──────────────────────────────┐                         ┌──────────────┐
 │ ftproxy (Node)               │                         │ Browser      │
 │  • crypto endpoint           │   TLS      TLS          │  • crypto    │
 │  • reads/writes files        │◄─────►Cloudflare◄──────►│    endpoint  │
 │  127.0.0.1:<port>            │  (quick tunnel)         │  • WebCrypto │
 │     ▲                        │  sees only: ciphertext, │              │
 │     │ reverse_proxy          │  chunk sizes, timing    │              │
 │  Caddy (hardened headers)    │                         │              │
 │     ▲                        │                         │              │
 │  cloudflared                 │                         │              │
 └──────────────────────────────┘                         └──────────────┘
 Link: https://<rand>.trycloudflare.com/r/<token>#k=<32-byte secret>
                                                   └─ never sent to any server
```

The Node process is an **endpoint**, not a relay: it decrypts and encrypts.
Cloudflare and Caddy only ever see ciphertext frames.

---

## 3. Repo layout

Fork SMSproxy into this directory, then:

```
src/
  crypto.js         CHANGED  HKDF_INFO -> 'transfer-session-v1' (no key reuse across tools)
  wslite.js         CHANGED  binary frames in/out, backpressure (drain)
  server.js         CHANGED  routes encrypted control envelope + binary chunks
  stream-crypto.js  NEW      per-file key, chunk seal/open (STREAM construction)
  transfer.js       NEW      transfer state machine, flow control, resume
  filetype.js       NEW      magic-byte detection, canonical extensions
  fsafe.js          NEW      filename sanitizer, quarantine writer (.part -> final)
  exif.js           NEW      JPEG metadata strip (APP1 Exif/XMP, APP13)
  sanitize.js       reused   also applied to every filename shown in the TUI
  tui.js            CHANGED  /send /accept /decline /cancel /files, progress bar
  caddy.js          CHANGED  CSP: img-src 'self' data: blob:
public/
  index.html        CHANGED  file picker, drop zone, offer card, progress, save
test/
  stream-crypto.test.js  filetype.test.js  fsafe.test.js  e2e.test.js
```

`index.html` mirrors `stream-crypto.js`, `filetype.js`, `exif.js` exactly (same as
SMSproxy's crypto mirroring). Keep a shared test vector file both sides check.

---

## 4. Cryptography

### 4.1 Session (unchanged)
`secret` (32 B, link fragment) → `HKDF-SHA256(secret, salt, info='transfer-session-v1')`
→ 64 B → `encKey` (AES-256-GCM) ‖ `macKey` (HMAC-SHA256). Auth = HMAC challenge
response; safety code = HMAC(macKey, 'transfer-safety-v1') → `XXXX-XXXX`.

### 4.2 Control envelope (new: metadata is secret too)
In SMSproxy, `typing`/`ack` travel as plaintext JSON. For files, **filename, size,
type, and hash are sensitive**, so every transfer control message is wrapped:

```
wire:   {"t":"x","data":"<b64u(iv ‖ AES-GCM(encKey, JSON(inner)))>"}
inner:  {"op":"offer", ...}   // op names in §5
```
Decrypt failure → `_tamper()` (same as a bad chat message).

### 4.3 Per-file key
```
fileId  = 16 random bytes, chosen by the sender per offer
fileKey = HKDF-SHA256(ikm=secret, salt=fileId, info='transfer-file-v1') -> 32 B AES-256-GCM
```
Unique key per file ⇒ deterministic counter nonces are safe (no nonce reuse
across files, no birthday bound to track).

### 4.4 Chunk seal (STREAM construction)
```
CHUNK      = 64 KiB plaintext (last chunk may be shorter, never empty unless size=0)
total      = max(1, ceil(size / CHUNK))          // ≤ 8000 at 500 MiB
nonce(i)   = 0x00000000 ‖ uint64_be(i)            // 12 bytes
header(i)  = 0x01 ‖ fileId(16) ‖ uint32_be(i) ‖ flags(1)   // 22 bytes, flags bit0 = isLast
ct(i)      = AES-GCM(fileKey, nonce(i), plaintext_i, AAD = header(i))
frame      = header(i) ‖ ct(i)                    // ≤ 22 + 65536 + 16 = 65,574 B < 128 KiB cap
```
The header is sent in the clear **and** authenticated as AAD, so:

| Attack | Why it fails |
|---|---|
| Reorder / replay chunk | index is in AAD and the nonce; receiver demands strictly `next` index |
| Splice chunk from another file | fileId in AAD + different fileKey |
| Truncate stream | no chunk with `isLast=1` at `total-1` → never completes |
| Extend stream | `isLast` before/after `total-1`, or index ≥ total → abort |
| Flip any bit | GCM tag fails |

### 4.5 Whole-file hash
Offer carries `sha256` of the exact bytes being sent (after EXIF strip). Receiver
hashes as it writes; mismatch at the end → fail + delete. It's belt-and-braces over
STREAM, and also the human-comparable fingerprint shown on the offer card (first
8 hex chars).

### 4.6 Failure policy
Any GCM failure on a chunk or envelope = **tamper** → both sides red **KEYS CHANGED**,
partial file deleted, link burns. Type mismatch / size violation / hash mismatch =
**transfer failed** (delete partial, keep session), but count it toward the tripwire.

---

## 5. Wire protocol

### 5.1 Control ops (inside the encrypted envelope)

| op | dir | fields | meaning |
|---|---|---|---|
| `offer` | sender→recv | `id` (b64u fileId), `name`, `size`, `type` (`txt\|png\|jpeg\|mp4\|pdf`), `sha256`, `stripped` (bool) | "I have this file" |
| `accept` | recv→sender | `id`, `from` (chunk index, 0 for fresh) | start/resume streaming |
| `decline` | recv→sender | `id` | no |
| `ack` | recv→sender | `id`, `next` (next expected index) | cumulative flow-control ack |
| `done` | recv→sender | `id`, `ok` (bool), `reason?` | receiver verified (or not) |
| `cancel` | either | `id`, `reason?` | abort; both sides delete partials |

Chunks themselves are **binary WS frames** (§4.4), not envelopes.

### 5.2 Rules
- **One active transfer per direction** (max 2 total). A second `offer` while one is
  pending/active in that direction → auto-decline `busy`. Keeps state and abuse small.
- Receiver rejects an `offer` before showing it if: `size > 524,288,000`, `size < 0`,
  `type` not allowlisted, `name` empty after sanitizing, or `sha256` not 64 hex.
- Pending offer expires after **120 s** without accept → auto-decline.
- Binary frames are accepted **only** from the authed active connection, only for
  the current accepted `fileId`, only with `index === next`. Anything else → close.

### 5.3 Flow control
- Sender keeps ≤ **16 chunks (1 MiB) unacked** in flight.
- Receiver sends `ack {next}` every 8 chunks and after the last.
- Node: honor `socket.write()` → `false` ⇒ wait `drain`. Browser: wait while
  `ws.bufferedAmount > 1 MiB`.

### 5.4 Resume (v1)
Ties into SMSproxy's existing reconnect ticket. On reconnect within the 45 s grace
window, the receiver re-sends `accept {id, from: next}`. The sender re-derives the
file key and continues from `from`. Receiver keeps its partial (`.part` file on host;
chunk array in browser tab). Hash state: receiver re-hashes the partial on resume
(cheap) rather than serializing hash state. Session burn → partials deleted.

### 5.5 State machine (per transfer, both sides)
```
          offer            accept              last chunk ok + hash ok
 (none) ───────► OFFERED ─────────► STREAMING ──────────────────────► DONE
                   │  │                 │  ▲
          decline/ │  │ 120s            │  │ reconnect + accept{from}
          expire   ▼  ▼                 ▼  │
                 DECLINED          PAUSED (grace) ──timeout──► FAILED
                                         │
   cancel / type mismatch / size violation / hash mismatch ──► FAILED (delete partial)
   GCM failure anywhere ─────────────────────────────────────► TAMPER (burn session)
```

---

## 6. File-type validation (receiver decides, always)

The sender's extension and declared `type` are **claims**. The receiver checks the
first chunk's bytes against the declared type and aborts on mismatch. The sender
also checks before offering (fail early, better UX), but that's not the control.

| type | rule (first bytes) | saved extension |
|---|---|---|
| png | `89 50 4E 47 0D 0A 1A 0A` | `.png` |
| jpeg | `FF D8 FF` | `.jpg` |
| pdf | `25 50 44 46 2D` (`%PDF-`) within first 1024 B | `.pdf` |
| mp4 | bytes 4 to 7 = `ftyp`, major brand in {`isom`,`iso2`,`mp41`,`mp42`,`avc1`,`M4V `,`dash`} | `.mp4` |
| txt | entire file decodes with `TextDecoder('utf-8',{fatal:true})` streaming, no `0x00` | `.txt` |

- txt is checked across **every** chunk (a binary payload can hide after valid text).
- The saved extension comes from the **detected** type, never from the sender's name.
- No SVG, no HTML, no archives, ever. (SVG/HTML carry script.)

---

## 7. Filenames (attacker-controlled input)

`fsafe.cleanName(name, detectedType)`:
1. Take the basename only (split on `/` and `\`); drop the sender's extension.
2. NFC-normalize. Strip C0/C1 controls, DEL, and bidi/format chars
   (`U+200B..U+200F`, `U+202A..U+202E`, `U+2066..U+2069`, `U+FEFF`).
3. Allow `[\p{L}\p{N} ._()-]`; replace the rest with `_`. Collapse repeats, trim dots/spaces.
4. Reject Windows reserved names (`CON`, `NUL`, `COM1`…). Empty → `file`.
5. Cap at 100 bytes UTF-8, then append the canonical extension.
6. Display in the TUI only through `sanitize()`; in the browser only via `textContent`.

---

## 8. Host side: receiving (guest → host)

- Inbox: `~/Downloads/ftproxy-inbox/` (flag `--inbox <dir>`), created `0700`.
- Write to `<inbox>/.<random>.part` with `open(O_CREAT|O_EXCL|O_WRONLY, 0600)`.
  Refuse if the inbox is a symlink. Never follow symlinks on write.
- On verified finish: `rename` to `<inbox>/<YYYYMMDD-HHMMSS>-<cleanName>`; on name
  clash add `-1`, `-2` (via `O_EXCL`, no check-then-write race).
- Disk-space check before accepting (`fs.statfs`): need `size + 64 MiB` free.
- **Never** auto-open, preview, or `cat` received files. TUI prints path + size + hash.
- On fail/cancel/burn: unlink the `.part`. On startup: sweep stale `.part` files.

## 9. Host side: sending (host → guest)

- `/send <path>`: resolve → `lstat` → must be a regular file (no symlink, no dir,
  no device), ≤ 500 MiB, detected type allowlisted.
- JPEG: strip metadata (§11) into a temp buffer before hashing/offer (JPEG > 50 MiB:
  send as-is with a warning). `--keep-meta` disables.
- Hash first (streaming sha256), then offer. Read chunks with `fs.read` at
  `index * CHUNK` (enables resume).
- Re-`fstat` on each chunk: if size/mtime changed mid-send → cancel `file changed`.

## 10. Browser side

**Receiving (host → guest)**
- Offer card: icon, cleaned name, size, type, hash prefix, **Accept / Decline**.
- `ws.binaryType = 'arraybuffer'`; chunks decrypted into an array of `Uint8Array`.
- Finish: hash → `new Blob(chunks, {type:'application/octet-stream'})` →
  `<a download="cleanName">` → click → `URL.revokeObjectURL` after save.
  The octet-stream type means the browser saves instead of rendering it in our origin.
- Memory: 500 MiB in-tab is OK on desktop; on low-RAM phones it may fail. Show a
  warning on offers > 200 MiB on mobile UAs. (v2: `showSaveFilePicker` streaming.)
- Optional preview: png/jpeg only, as `<img src=blob:>` after verification. No
  inline PDF/MP4/TXT rendering.

**Sending (guest → host)**
- `<input type=file accept=".txt,.png,.jpg,.jpeg,.mp4,.pdf">` + drag-and-drop zone.
- Type detected from bytes (not `File.type`). JPEG metadata stripped by default
  (toggle visible on the card). Hash via chunked SHA-256: WebCrypto has no
  streaming digest, so ship a small mirrored SHA-256 implementation (tested against
  the Node vectors), or hash `File.arrayBuffer()` for ≤ 500 MiB. Pick at build time; the
  mirrored impl is the safer memory choice.
- `File.slice(i*CHUNK, (i+1)*CHUNK)` → encrypt → send.

**UI quality bar** (per global standards): 44×44 px targets, 4.5:1 contrast,
keyboard-operable drop zone (Enter/Space opens the picker), `aria-live="polite"`
progress text, `prefers-reduced-motion` respected, inline SVG icons (Lucide), light
and dark tokens. Same visual language as SMSproxy's bubble UI.

## 11. Metadata stripping (JPEG)

Walk JPEG segments from SOI; drop `APP1` (Exif, XMP) and `APP13` (IPTC/Photoshop);
keep `APP0` (JFIF), `APP2` (ICC color profile), `DQT/DHT/SOF/SOS` and the scan data.
Lossless, no re-encode. Malformed structure → refuse to strip, ask to send as-is.
PNG (`eXIf`, `tEXt`, `iTXt` chunks) is v2. MP4 metadata: out of scope (documented).

---

## 12. Threat model → controls

| Threat | Control |
|---|---|
| Network/Cloudflare reads files | E2E AES-256-GCM; key only in fragment |
| Someone else uses the link | 1 seat, HMAC auth, reconnect ticket, tripwire (inherited) |
| Chunk tamper/reorder/truncate | STREAM construction §4.4, hash §4.5, tamper → burn |
| Sender lies about type | receiver magic-byte check §6; extension from detected type |
| Path traversal / RLO / ANSI in names | §7 sanitizer; files written only into inbox |
| Overwrite / symlink attacks on host | `O_EXCL`, `0600`, no-follow, timestamped names §8 |
| Disk / memory exhaustion | 500 MiB cap enforced at offer *and* stream; statfs; 1 transfer/direction |
| Unwanted push | offer → explicit accept; 120 s expiry |
| GPS leak in photos | JPEG metadata strip on by default §11 |
| Malicious content auto-executing | octet-stream download, never auto-open, no PDF/MP4 inline |

### Residual risks (say these plainly in the README)
1. **Web-delivered JS.** The guest's crypto code is served through Cloudflare's TLS
   edge. A malicious edge could serve modified JS that leaks `#k=`; the safety code
   can't catch it (tampered JS can display the right one). Fix = v2 CLI↔CLI mode.
2. **Size/timing leak.** The network sees ~file size (chunk count) and timing.
   Optional padding is v2.
3. **First-tap race** (inherited): whoever opens the link first gets the seat.
4. **Valid ≠ safe.** A real PDF/MP4 can still exploit a vulnerable viewer. We prove
   the type, not the intent. Open untrusted files in a patched or sandboxed viewer.
5. **Not audited.**

---

## 13. Server/wslite changes (concrete)

- `wslite`: in `_frame` reassembly, `op === 0x2` → `emit('binary', Buffer)`. Keep
  `MAX_MESSAGE` at 128 KiB (chunks fit; the abuse guard stays). Add
  `sendBinary(buf)` (opcode `0x2`) returning `socket.write()`'s boolean; re-emit `drain`.
- `server.js`: on `binary` from anyone other than the authed active conn → close
  `1008`. Forward the envelope `t:'x'` and binary frames to `transfer.js`.
- `caddy.js` CSP: `img-src 'self' data: blob:` (previews). Nothing else loosens.

## 14. CLI / TUI

```
/send <path>     offer a file to the guest (tab-completes paths)
/accept          accept the pending incoming offer
/decline         decline it
/cancel          abort the active transfer(s)
/files           list this session's transfers + saved paths
/safety  /help  /quit     (inherited)
```
Incoming offer renders as a boxed card: name, size, type, hash prefix, `[a]ccept [d]ecline`.
Progress: `▕██████░░░░▏ 61%  31.2/51.0 MiB  4.8 MiB/s  eta 4s`.
A text chat line remains (for the safety-code readout and "sending you the PDF now").

---

## 15. Test plan

**Unit**
- stream-crypto: round-trip at sizes 0, 1, 65535, 65536, 65537, 500 MiB(sim);
  must FAIL on: swapped chunks, dropped middle chunk, dropped last chunk, extra chunk,
  chunk from another fileId, flipped bit in header / ct / tag, wrong `isLast`.
- Node ↔ browser vectors: same secret+fileId+chunk → identical frame bytes.
- filetype: each allowed type passes; PNG-renamed-.pdf fails; txt with NUL at
  byte 70,000 fails; polyglot (`%PDF-` after 1024 B) fails.
- fsafe: `../../etc/passwd`, `a‮fdp.exe`, `\x1b]52;c;…`, `CON`, 300-byte names,
  emoji, empty → all produce safe names inside the inbox.
- exif: stripped output has no APP1/APP13, decodes identically (pixel compare).

**E2E** (extend `test/e2e.test.js`)
- host→guest and guest→host, each type; 500 MiB exact passes, 500 MiB+1 rejected
  at offer **and** when the stream overruns a lying offer.
- decline, expiry, cancel mid-stream (partials deleted).
- kill the WS mid-transfer → reconnect with ticket → resumes from `next` → hash OK.
- injected bad chunk → both sides tamper → link burns.
- second offer while busy → auto-decline.

**Through the tunnel (manual, must actually run)**
- HYPOTHESIS: Cloudflare quick tunnels pass 64 KiB binary WS frames without a size
  limit, and throughput is usable for 500 MiB. Confirm with a real 500 MiB transfer
  over `trycloudflare.com`; record the throughput in the README.

---

## 16. Milestones

**v0: host → guest, one file**
- fork + rename HKDF info strings; wslite binary; stream-crypto + vectors;
  filetype; offer/accept/decline/cancel; browser receive + download; TUI `/send`.
- Done when: a 500 MiB MP4 goes host→guest over the tunnel, hash matches, and every
  stream-crypto negative test fails closed.

**v1: both directions + hardening**
- guest→host send, inbox writer (§8), fsafe, JPEG strip, resume, flow-control
  tuning, statfs check, expiry, full e2e suite.
- Done when: the whole §15 suite passes and a reconnect mid-transfer resumes.

**v2: polish**
- `showSaveFilePicker` streaming (Chromium), PNG metadata strip, optional size
  padding, **CLI↔CLI mode** (closes residual risk #1), README security section.
