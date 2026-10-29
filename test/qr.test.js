'use strict';
// QR encoder tests (src/qr.js). Known answers from the ISO/IEC 18004 tables for
// the constant parts (RS, format/version BCH, alignment, capacities), plus an
// independent reader that decodes every code back: format bits, unmask, zigzag,
// de-interleave, Reed-Solomon syndromes, byte-mode parse. Its GF maths (log
// tables) and mask formulas (spec's row/column form) are written separately
// from the encoder's so one bug can't hide in both.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const qr = require('../src/qr');
const r = require('../src/render');

const EXP = new Array(512), LOG = new Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
// A valid RS codeword evaluates to 0 at every generator root a^0..a^(nEcc-1).
function syndromesZero(block, nEcc) {
  for (let i = 0; i < nEcc; i++) {
    let s = 0;
    for (const c of block) s = mul(s, EXP[i]) ^ c;
    if (s) return false;
  }
  return true;
}

// Spec form: i = row, j = column.
const SPEC_MASKS = [
  (i, j) => (i + j) % 2 === 0,
  (i) => i % 2 === 0,
  (i, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i * j) % 3) + ((i + j) % 2)) % 2 === 0,
];

function readBack(code) {
  const { size, modules: m, isFunction: fn, version: ver } = code;
  let f1 = 0, f2 = 0;
  const p1 = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  p1.forEach(([x, y], i) => { f1 |= m[y][x] << i; });
  for (let i = 0; i < 8; i++) f2 |= m[8][size - 1 - i] << i;
  for (let i = 8; i < 15; i++) f2 |= m[size - 15 + i][8] << i;
  assert.equal(f2, f1, 'the two format copies disagree');
  assert.equal(m[size - 8][8], 1, 'dark module missing');
  const fv = f1 ^ 0x5412;
  const ecl = ['M', 'L', 'H', 'Q'][fv >>> 13], mask = (fv >>> 10) & 7;
  assert.equal(f1, qr.formatBits(ecl, mask), 'format BCH');

  const bits = [];
  let up = true;
  for (let right = size - 1; right >= 1; right -= 2, up = !up) {
    if (right === 6) right = 5;
    for (let k = 0; k < size; k++) {
      const y = up ? size - 1 - k : k;
      for (const x of [right, right - 1]) if (!fn[y][x]) bits.push(m[y][x] ^ (SPEC_MASKS[mask](y, x) ? 1 : 0));
    }
  }
  const raw = qr.rawCodewords(ver);
  assert.ok(bits.length >= raw * 8 && bits.length < raw * 8 + 8, 'codeword capacity');
  const cw = [];
  for (let i = 0; i < raw; i++) cw.push(bits.slice(i * 8, i * 8 + 8).reduce((a, b) => (a << 1) | b, 0));

  const nB = qr.NUM_BLOCKS[ecl][ver], nEcc = qr.ECC_PER_BLOCK[ecl][ver];
  const nShort = nB - (raw % nB), shortData = Math.floor(raw / nB) - nEcc;
  const blocks = Array.from({ length: nB }, () => []);
  let k = 0;
  for (let i = 0; i <= shortData; i++) for (let j = 0; j < nB; j++) if (i < shortData || j >= nShort) blocks[j].push(cw[k++]);
  const data = blocks.flatMap((b) => b.slice());
  for (let i = 0; i < nEcc; i++) for (let j = 0; j < nB; j++) blocks[j].push(cw[k++]);
  assert.equal(k, raw);
  blocks.forEach((b, j) => assert.ok(syndromesZero(b, nEcc), `RS block ${j} invalid`));

  const dbits = data.flatMap((b) => [7, 6, 5, 4, 3, 2, 1, 0].map((s) => (b >>> s) & 1));
  let pos = 0;
  const take = (n) => { let v = 0; for (let i = 0; i < n; i++) v = (v << 1) | dbits[pos++]; return v; };
  assert.equal(take(4), 0b0100, 'byte mode');
  const len = take(qr.ccBits(ver));
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = take(8);
  return { text: out.toString('utf8'), ecl, mask, version: ver };
}

// A link shaped like a real quick-tunnel one: 4-word host, 24-byte token, 32-byte key.
function fakeLink(host = 'absolute-quantity-weekly-monitored') {
  return `https://${host}.trycloudflare.com/r/${crypto.randomBytes(24).toString('base64url')}#k=${crypto.randomBytes(32).toString('base64url')}`;
}

test('Reed-Solomon matches the published 1-M "HELLO WORLD" example', () => {
  const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
  assert.deepEqual(qr.rsRemainder(data, qr.rsDivisor(10)), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
});

test('format bits match the spec table for L and M, all 8 masks', () => {
  const M = ['101010000010010', '101000100100101', '101111001111100', '101101101001011', '100010111111001', '100000011001110', '100111110010111', '100101010100000'];
  const L = ['111011111000100', '111001011110011', '111110110101010', '111100010011101', '110011000101111', '110001100011000', '110110001000001', '110100101110110'];
  for (let k = 0; k < 8; k++) {
    assert.equal(qr.formatBits('M', k), parseInt(M[k], 2), `M mask ${k}`);
    assert.equal(qr.formatBits('L', k), parseInt(L[k], 2), `L mask ${k}`);
  }
});

test('version bits and alignment positions match the spec table', () => {
  assert.equal(qr.versionBits(7), 0x07c94);
  assert.equal(qr.versionBits(8), 0x085bc);
  assert.equal(qr.versionBits(9), 0x09a99);
  assert.equal(qr.versionBits(10), 0x0a4d3);
  assert.deepEqual(qr.alignPositions(1), []);
  assert.deepEqual(qr.alignPositions(2), [6, 18]);
  assert.deepEqual(qr.alignPositions(6), [6, 34]);
  assert.deepEqual(qr.alignPositions(7), [6, 22, 38]);
  assert.deepEqual(qr.alignPositions(9), [6, 26, 46]);
  assert.deepEqual(qr.alignPositions(10), [6, 28, 50]);
});

test('byte capacity per version matches the spec table, and the boundaries hold', () => {
  const CAP = { M: [14, 26, 42, 62, 84, 106, 122, 152, 180, 213], L: [17, 32, 53, 78, 106, 134, 154, 192, 230, 271] };
  for (const ecl of ['L', 'M']) {
    CAP[ecl].forEach((cap, i) => {
      const v = i + 1;
      assert.equal(qr.encode('a'.repeat(cap), ecl).version, v, `${ecl} v${v} fits ${cap}`);
      if (v < qr.MAX_VERSION) assert.equal(qr.encode('a'.repeat(cap + 1), ecl).version, v + 1, `${ecl} v${v} overflows at ${cap + 1}`);
      else assert.throws(() => qr.encode('a'.repeat(cap + 1), ecl), /too long/);
    });
  }
});

test('every version, both levels, decodes back to the exact input', () => {
  const CAP = { M: [14, 26, 42, 62, 84, 106, 122, 152, 180, 213], L: [17, 32, 53, 78, 106, 134, 154, 192, 230, 271] };
  for (const ecl of ['L', 'M']) {
    for (const cap of CAP[ecl]) {
      for (const len of [cap, cap - 3]) {
        const text = crypto.randomBytes(len).toString('base64url').slice(0, len);
        const got = readBack(qr.encode(text, ecl));
        assert.equal(got.text, text);
        assert.equal(got.ecl, ecl);
      }
    }
  }
  assert.equal(readBack(qr.encode('', 'M')).text, '');
  assert.equal(readBack(qr.encode('café → ok', 'M')).text, 'café → ok');
});

test('every one of the 8 masks decodes, and auto-pick varies with content', () => {
  const text = fakeLink();
  for (let k = 0; k < 8; k++) {
    const code = qr.encode(text, 'M', { mask: k });
    assert.equal(code.mask, k);
    const got = readBack(code);
    assert.equal(got.text, text, `mask ${k}`);
    assert.equal(got.mask, k);
  }
  const seen = new Set();
  for (let i = 0; i < 100; i++) {
    const t = fakeLink();
    const code = qr.encode(t, 'M');
    assert.equal(readBack(code).text, t);
    seen.add(code.mask);
  }
  assert.ok(seen.size >= 4, `auto-pick should vary with content, saw ${[...seen]}`);
});

test('a real-shaped tunnel link fits an 80-column terminal', () => {
  for (const host of ['a-b-c-d', 'absolute-quantity-weekly-monitored', 'professional-accommodation-interpretation-requirements']) {
    const link = fakeLink(host);
    const code = qr.encode(link, 'M');
    assert.equal(readBack(code).text, link);
    const { width } = r.qrLines(code, { color: false, unicode: true });
    assert.ok(width + 2 <= 80, `${link.length} bytes -> v${code.version}, ${width} cols`);
  }
});

test('the half-block renderer draws exactly the modules plus a 4-module light quiet zone', () => {
  const code = qr.encode(fakeLink(), 'M');
  const { lines, width } = r.qrLines(code, { color: false, unicode: true });
  const n = code.size + 8;
  assert.equal(width, n);
  assert.equal(lines.length, Math.ceil(n / 2));
  const TOP = { ' ': [0, 0], '▀': [1, 0], '▄': [0, 1], '█': [1, 1] };
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      const [t, b] = TOP[lines[y >> 1][x]];
      const got = y % 2 ? b : t;
      const inside = x >= 4 && y >= 4 && x < code.size + 4 && y < code.size + 4;
      assert.equal(got, inside ? code.modules[y - 4][x - 4] : 0, `module (${x},${y})`);
    }
  }
  const wide = r.qrLines(code, { color: false, unicode: false });
  assert.equal(wide.width, 2 * n);
  assert.match(wide.lines.join(''), /^[# ]+$/, 'non-UTF-8 fallback is pure ASCII');
  const coloured = r.qrLines(code, { color: true, unicode: true });
  assert.ok(coloured.lines.every((l) => l.endsWith('\x1b[0m')), 'colour reset at each line end');
});

test('qrBlock refuses to print a code the terminal would wrap', () => {
  const saved = process.stdout.columns;
  try {
    process.stdout.columns = 40;
    assert.match(r.qrBlock(fakeLink()), /needs \d+ columns, this terminal has 40/);
    process.stdout.columns = 120;
    assert.match(r.qrBlock(fakeLink()), /SCAN TO JOIN/);
  } finally { process.stdout.columns = saved; }
  assert.match(r.qrBlock('x'.repeat(400)), /no QR code: too long/);
});

test('utf8Locale reads LC_ALL > LC_CTYPE > LANG', () => {
  assert.equal(r.utf8Locale({ LANG: 'en_US.UTF-8' }), true);
  assert.equal(r.utf8Locale({ LANG: 'C' }), false);
  assert.equal(r.utf8Locale({ LC_ALL: 'C', LANG: 'en_US.UTF-8' }), false);
  assert.equal(r.utf8Locale({}), true);
});
