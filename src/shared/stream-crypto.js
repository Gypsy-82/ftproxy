// File-chunk and control-envelope crypto. DESIGN.md §4, plus two bindings the
// spec didn't have, both aimed at the one party we assume is hostile on the
// wire: the TLS-terminating edge (Cloudflare), which can drop, replay, reorder
// and REFLECT frames but cannot decrypt them.
//
//   * DIRECTION. Host and guest share one session key, so without a direction
//     the edge could bounce the host's own envelope back at the host and it
//     would decrypt cleanly. Every envelope AAD and every file key now carries
//     a direction byte, so a reflected frame fails authentication.
//   * CONNECTION + SEQUENCE. Envelopes are bound to (server challenge ‖ client
//     nonce ‖ seq). Both halves are fresh per connection, so frames recorded on
//     one connection are useless on the next, and the strict seq kills replay
//     and reordering within a connection.
//
// Chunk frame (§4.4):
//   header(i) = 0x01 ‖ fileId(16) ‖ uint32_be(i) ‖ flags(1)    flags bit0 = isLast
//   nonce(i)  = 0x00000000 ‖ uint64_be(i)
//   frame     = header(i) ‖ AES-256-GCM(fileKey, nonce(i), pt_i, AAD = header(i))
//   fileKey   = HKDF-SHA256(ikm = secret, salt = fileId, info = 'transfer-file-v1' ‖ dir)
//
// ISOMORPHIC: runs in Node and is inlined verbatim into the guest page.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('stream-crypto', function () {
  'use strict';

  const subtle = globalThis.crypto.subtle;
  const te = new TextEncoder();
  const td = new TextDecoder();

  const CHUNK = 64 * 1024;
  const HDR = 22;
  const TAG = 16;
  const VERSION = 0x01;
  const MAX_SIZE = 500 * 1024 * 1024;     // 524,288,000
  const MAX_INFLIGHT = 16;                 // chunks unacked (1 MiB)
  const ACK_EVERY = 8;
  const DIR = { H2G: 1, G2H: 2 };
  const FILE_INFO = te.encode('transfer-file-v1');
  const ENV_INFO = te.encode('transfer-ctl-v1');
  const BIND_BYTES = 48;                   // challenge(32) ‖ client nonce(16)

  // ---- bytes ----
  function randomBytes(n) { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; }
  function concat(...parts) {
    let n = 0; for (const p of parts) n += p.length;
    const out = new Uint8Array(n); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  function toB64u(bytes) {
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // Strict: rejects anything that isn't canonical unpadded base64url, so a
  // malformed field is an error, never a silently "close enough" decode.
  function fromB64u(s) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('bad base64url');
    let t = s.replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) t += '=';
    const b = atob(t);
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    if (toB64u(u) !== s) throw new Error('non-canonical base64url');
    return u;
  }
  function toHex(u) { let s = ''; for (let i = 0; i < u.length; i++) s += u[i].toString(16).padStart(2, '0'); return s; }
  function u64be(n) {
    const b = new Uint8Array(8);
    const hi = Math.floor(n / 0x100000000), lo = n >>> 0;
    b[0] = hi >>> 24; b[1] = hi >>> 16; b[2] = hi >>> 8; b[3] = hi;
    b[4] = lo >>> 24; b[5] = lo >>> 16; b[6] = lo >>> 8; b[7] = lo;
    return b;
  }
  function checkDir(dir) { if (dir !== DIR.H2G && dir !== DIR.G2H) throw new Error('bad direction'); }

  // ---- sizes ----
  function totalChunks(size) { return Math.max(1, Math.ceil(size / CHUNK)); }
  function expectedLen(size, i) {
    const total = totalChunks(size);
    return i < total - 1 ? CHUNK : size - (total - 1) * CHUNK;
  }

  // ---- keys ----
  async function importSecret(secretBytes) {
    if (!(secretBytes instanceof Uint8Array) || secretBytes.length !== 32) throw new Error('secret must be 32 bytes');
    return subtle.importKey('raw', secretBytes, 'HKDF', false, ['deriveBits']);
  }
  async function fileKey(base, fileId, dir) {
    if (!(fileId instanceof Uint8Array) || fileId.length !== 16) throw new Error('fileId must be 16 bytes');
    checkDir(dir);
    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: fileId, info: concat(FILE_INFO, [dir]) }, base, 256);
    return subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  // ---- chunks ----
  function header(fileId, index, isLast) {
    const h = new Uint8Array(HDR);
    h[0] = VERSION;
    h.set(fileId, 1);
    h[17] = index >>> 24; h[18] = index >>> 16; h[19] = index >>> 8; h[20] = index;
    h[21] = isLast ? 1 : 0;
    return h;
  }
  function nonce(index) { return concat(new Uint8Array(4), u64be(index)); }

  async function sealChunk(key, fileId, index, isLast, pt) {
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new Error('bad chunk index');
    if (pt.length > CHUNK) throw new Error('chunk too large');
    const h = header(fileId, index, isLast);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce(index), additionalData: h }, key, pt));
    return concat(h, ct);
  }

  // Parse the clear header WITHOUT trusting it; openChunk() is what proves it.
  function parseHeader(frame) {
    if (!(frame instanceof Uint8Array) || frame.length < HDR + TAG || frame.length > HDR + CHUNK + TAG) return null;
    if (frame[0] !== VERSION) return null;
    if (frame[21] & 0xfe) return null;                     // unknown flag bits set
    return {
      fileId: frame.subarray(1, 17),
      index: ((frame[17] << 24) | (frame[18] << 16) | (frame[19] << 8) | frame[20]) >>> 0,
      isLast: frame[21] === 1,
    };
  }

  // Throws on ANY modification of header or ciphertext (GCM tag).
  async function openChunk(key, frame, index) {
    const h = frame.subarray(0, HDR);
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: nonce(index), additionalData: h }, key, frame.subarray(HDR));
    return new Uint8Array(pt);
  }

  // ---- control envelopes ----
  function envAad(dir, bind, seq) {
    checkDir(dir);
    if (!(bind instanceof Uint8Array) || bind.length !== BIND_BYTES) throw new Error('bad connection binding');
    if (!Number.isSafeInteger(seq) || seq < 1) throw new Error('bad seq');
    return concat(ENV_INFO, [dir], bind, u64be(seq));
  }
  async function sealEnv(encKey, dir, bind, seq, obj) {
    const iv = randomBytes(12);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: envAad(dir, bind, seq) }, encKey, te.encode(JSON.stringify(obj))));
    return toB64u(concat(iv, ct));
  }
  async function openEnv(encKey, dir, bind, seq, data) {
    const raw = fromB64u(data);
    if (raw.length < 12 + TAG) throw new Error('short envelope');
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, 12), additionalData: envAad(dir, bind, seq) }, encKey, raw.subarray(12));
    const obj = JSON.parse(td.decode(pt));
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('envelope is not an object');
    return obj;
  }

  return {
    CHUNK, HDR, TAG, VERSION, MAX_SIZE, MAX_INFLIGHT, ACK_EVERY, DIR, BIND_BYTES,
    randomBytes, concat, toB64u, fromB64u, toHex, u64be,
    totalChunks, expectedLen,
    importSecret, fileKey, header, nonce, sealChunk, parseHeader, openChunk,
    envAad, sealEnv, openEnv,
  };
});
