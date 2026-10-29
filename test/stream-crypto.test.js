'use strict';
// STREAM construction (DESIGN.md §4.4) — round trips and every negative case
// from §15, plus the envelope bindings (direction, connection, seq).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const sc = require('../src/shared/stream-crypto');

const SECRET = new Uint8Array(32).map((_, i) => i + 1);
const FID = new Uint8Array(16).map((_, i) => 0xa0 + i);
const FID2 = new Uint8Array(16).map((_, i) => 0x10 + i);

async function sealAll(key, fid, data) {
  const total = sc.totalChunks(data.length);
  const frames = [];
  for (let i = 0; i < total; i++) {
    const pt = data.subarray(i * sc.CHUNK, i * sc.CHUNK + sc.expectedLen(data.length, i));
    frames.push(await sc.sealChunk(key, fid, i, i === total - 1, pt));
  }
  return frames;
}

// The receiver's rules from engine._rxChunk, minus I/O: strict next index,
// isLast exactly at total-1, exact chunk lengths, GCM over everything.
async function receive(key, fid, size, frames) {
  const total = sc.totalChunks(size);
  const out = [];
  let next = 0;
  for (const f of frames) {
    if (next === total) throw new Error('stream extended past its last chunk');
    const h = sc.parseHeader(f);
    if (!h) throw new Error('malformed');
    if (sc.toB64u(h.fileId) !== sc.toB64u(fid)) throw new Error('wrong file');
    if (h.index !== next) throw new Error('out of order');
    const pt = await sc.openChunk(key, f, next);
    if (h.isLast !== (next === total - 1)) throw new Error('length mismatch');
    if (pt.length !== sc.expectedLen(size, next)) throw new Error('size');
    out.push(pt); next++;
  }
  if (next !== total) throw new Error('truncated');
  return Buffer.concat(out);
}

test('frame sizes and constants match the spec', () => {
  assert.equal(sc.HDR, 22);
  assert.equal(sc.MAX_SIZE, 524288000);
  assert.equal(sc.totalChunks(sc.MAX_SIZE), 8000);
  assert.equal(sc.totalChunks(0), 1);
  assert.ok(sc.HDR + sc.CHUNK + sc.TAG < 128 * 1024, 'max frame fits under wslite cap');
});

test('round-trip at boundary sizes', async () => {
  const base = await sc.importSecret(SECRET);
  const key = await sc.fileKey(base, FID, sc.DIR.H2G);
  for (const size of [0, 1, 65535, 65536, 65537, 3 * 65536 + 17]) {
    const data = new Uint8Array(size).map((_, i) => (i * 31) & 0xff);
    const got = await receive(key, FID, size, await sealAll(key, FID, data));
    assert.ok(Buffer.from(data).equals(got), `size ${size}`);
  }
});

test('500 MiB is 8000 chunks with a short-free last chunk (simulated)', () => {
  assert.equal(sc.expectedLen(sc.MAX_SIZE, 7999), 65536);
  assert.equal(sc.expectedLen(sc.MAX_SIZE + 1, 8000), 1);
});

test('every tamper/stream attack fails closed', async () => {
  const base = await sc.importSecret(SECRET);
  const key = await sc.fileKey(base, FID, sc.DIR.H2G);
  const other = await sc.fileKey(base, FID2, sc.DIR.H2G);
  const size = 4 * 65536 + 100;
  const data = new Uint8Array(size).map((_, i) => i & 0xff);
  const fr = await sealAll(key, FID, data);
  const foreign = await sealAll(other, FID2, data);
  const flip = (f, at) => { const g = new Uint8Array(f); g[at] ^= 1; return g; };
  const lastFlag = (f, v) => { const g = new Uint8Array(f); g[21] = v; return g; };

  const cases = {
    'swapped chunks': [fr[0], fr[2], fr[1], fr[3], fr[4]],
    'dropped middle chunk': [fr[0], fr[1], fr[3], fr[4]],
    'dropped last chunk': fr.slice(0, 4),
    'replayed chunk': [fr[0], fr[0], fr[1], fr[2], fr[3], fr[4]],
    'extra chunk after last': [...fr, fr[4]],
    'chunk from another fileId': [fr[0], foreign[1], fr[2], fr[3], fr[4]],
    'foreign chunk relabelled with our fileId': [fr[0], (() => { const g = new Uint8Array(foreign[1]); g.set(FID, 1); return g; })(), fr[2], fr[3], fr[4]],
    'flipped bit in header index': [fr[0], flip(fr[1], 20), fr[2], fr[3], fr[4]],
    'flipped bit in header fileId': [fr[0], flip(fr[1], 5), fr[2], fr[3], fr[4]],
    'flipped bit in ciphertext': [fr[0], flip(fr[1], 1000), fr[2], fr[3], fr[4]],
    'flipped bit in tag': [fr[0], flip(fr[1], fr[1].length - 1), fr[2], fr[3], fr[4]],
    'isLast set early': [fr[0], lastFlag(fr[1], 1)],
    'isLast cleared on last': [fr[0], fr[1], fr[2], fr[3], lastFlag(fr[4], 0)],
    'unknown flag bits': [fr[0], lastFlag(fr[1], 2), fr[2], fr[3], fr[4]],
  };
  for (const [name, frames] of Object.entries(cases)) {
    await assert.rejects(receive(key, FID, size, frames), undefined, name);
  }
});

test('file keys differ by direction: a reflected chunk does not open', async () => {
  const base = await sc.importSecret(SECRET);
  const h2g = await sc.fileKey(base, FID, sc.DIR.H2G);
  const g2h = await sc.fileKey(base, FID, sc.DIR.G2H);
  const f = await sc.sealChunk(h2g, FID, 0, true, new Uint8Array([1, 2, 3]));
  await assert.rejects(sc.openChunk(g2h, f, 0));
});

test('envelope: direction, connection binding and seq are all authenticated', async () => {
  const k = await globalThis.crypto.subtle.importKey('raw', new Uint8Array(32).fill(7), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const bindA = new Uint8Array(48).fill(1), bindB = new Uint8Array(48).fill(2);
  const d = await sc.sealEnv(k, sc.DIR.H2G, bindA, 1, { op: 'msg', text: 'hi' });
  assert.deepEqual(await sc.openEnv(k, sc.DIR.H2G, bindA, 1, d), { op: 'msg', text: 'hi' });
  await assert.rejects(sc.openEnv(k, sc.DIR.G2H, bindA, 1, d), undefined, 'reflected (wrong direction)');
  await assert.rejects(sc.openEnv(k, sc.DIR.H2G, bindB, 1, d), undefined, 'replayed into another connection');
  await assert.rejects(sc.openEnv(k, sc.DIR.H2G, bindA, 2, d), undefined, 'replayed at another seq');
  const raw = sc.fromB64u(d); raw[20] ^= 1;
  await assert.rejects(sc.openEnv(k, sc.DIR.H2G, bindA, 1, sc.toB64u(raw)), undefined, 'bit flip');
});

test('base64url decoding is strict', () => {
  assert.throws(() => sc.fromB64u('ab+c'));
  assert.throws(() => sc.fromB64u('abc='));
  assert.throws(() => sc.fromB64u('a'));
  assert.throws(() => sc.fromB64u('AB'), undefined, 'non-canonical trailing bits');
  assert.deepEqual([...sc.fromB64u('AQI')], [1, 2]);
});

// Fixed vectors: the browser runs this same file (inlined), so these pin the
// wire format itself — any accidental change to header/nonce/KDF shows up here.
test('known-answer vectors', async () => {
  const vec = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));
  const base = await sc.importSecret(new Uint8Array(Buffer.from(vec.ikmHex, 'hex')));
  for (const v of vec.chunks) {
    const key = await sc.fileKey(base, sc.fromB64u(v.fileId), v.dir);
    const pt = new TextEncoder().encode(v.plaintext);
    const f = await sc.sealChunk(key, sc.fromB64u(v.fileId), v.index, v.isLast, pt);
    assert.equal(sc.toHex(f), v.frame, `vector ${v.index}/${v.dir}`);
  }
});
