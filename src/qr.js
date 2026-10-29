'use strict';
// QR Code encoder (ISO/IEC 18004) for the share link: byte mode, versions
// 1-10, error correction L or M. In-house on purpose - the link carries the
// session key, so it goes to no third-party library and never to disk; it is
// drawn straight to the terminal (render.qrBlock). Layout and mask search
// follow Project Nayuki's reference QR generator (MIT).

const MAX_VERSION = 10;
const ECL_BITS = { L: 1, M: 0 };
// Index = version (0 unused): EC codewords per block, number of blocks.
const ECC_PER_BLOCK = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26],
};
const NUM_BLOCKS = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5],
};

const sizeOf = (ver) => ver * 4 + 17;
const ccBits = (ver) => (ver <= 9 ? 8 : 16);

// Codewords the symbol holds once finder/timing/alignment/format/version are placed.
function rawCodewords(ver) {
  let bits = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    bits -= (25 * n - 10) * n - 55;
    if (ver >= 7) bits -= 36;
  }
  return Math.floor(bits / 8);
}
const dataCodewords = (ver, ecl) => rawCodewords(ver) - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver];

function alignPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const step = Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
  const out = [6];
  for (let pos = sizeOf(ver) - 7; out.length < n; pos -= step) out.splice(1, 0, pos);
  return out;
}

// GF(2^8) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}
// Generator polynomial with roots a^0..a^(degree-1), leading 1 dropped.
function rsDivisor(degree) {
  const r = new Array(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = gfMul(r[j], root);
      if (j + 1 < r.length) r[j] ^= r[j + 1];
    }
    root = gfMul(root, 2);
  }
  return r;
}
function rsRemainder(data, divisor) {
  const r = new Array(divisor.length).fill(0);
  for (const b of data) {
    const f = b ^ r.shift();
    r.push(0);
    divisor.forEach((c, i) => { r[i] ^= gfMul(c, f); });
  }
  return r;
}

function formatBits(ecl, mask) {
  const data = (ECL_BITS[ecl] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}
function versionBits(ver) {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (ver << 12) | rem;
}

// Split into RS blocks, append each block's EC codewords, interleave.
function addEcc(data, ver, ecl) {
  const nBlocks = NUM_BLOCKS[ecl][ver], eccLen = ECC_PER_BLOCK[ecl][ver], raw = rawCodewords(ver);
  const nShort = nBlocks - (raw % nBlocks), shortLen = Math.floor(raw / nBlocks);
  const div = rsDivisor(eccLen);
  const blocks = [];
  let k = 0;
  for (let i = 0; i < nBlocks; i++) {
    const len = shortLen - eccLen + (i < nShort ? 0 : 1);
    const dat = data.slice(k, k + len);
    k += len;
    const ecc = rsRemainder(dat, div);
    if (i < nShort) dat.push(0);                 // placeholder, skipped below
    blocks.push(dat.concat(ecc));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= nShort) out.push(b[i]); });
  }
  return out;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

// Standard penalty rules N1-N4; the lowest-scoring mask is the easiest to scan.
function penalty(m) {
  const n = m.length;
  let p = 0, dark = 0;
  const get = (row, a, b) => (row ? m[a][b] : m[b][a]);
  const P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  for (const row of [true, false]) {
    for (let a = 0; a < n; a++) {
      let run = 1;
      for (let b = 1; b < n; b++) {
        if (get(row, a, b) === get(row, a, b - 1)) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
        else run = 1;
      }
      for (let b = 0; b + 11 <= n; b++) {
        if (P1.every((v, i) => get(row, a, b + i) === v)) p += 40;
        if (P2.every((v, i) => get(row, a, b + i) === v)) p += 40;
      }
    }
  }
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
    }
  }
  for (const r of m) for (const v of r) dark += v;
  const total = n * n;
  return p + (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
}

// -> { version, size, ecl, mask, modules, isFunction }; modules[y][x] is 1 for dark.
// `mask` forces one of the 8 masks (tests); by default the lowest penalty wins.
function encode(text, ecl = 'M', { mask = -1 } = {}) {
  if (!(ecl in ECL_BITS)) throw new Error('error correction must be L or M');
  const bytes = Buffer.from(String(text), 'utf8');
  let ver = 1;
  while (4 + ccBits(ver) + bytes.length * 8 > dataCodewords(ver, ecl) * 8) {
    if (++ver > MAX_VERSION) throw new Error(`too long for a terminal QR code (${bytes.length} bytes)`);
  }

  const cap = dataCodewords(ver, ecl) * 8;
  const bits = [];
  const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0b0100, 4);                                // byte mode
  push(bytes.length, ccBits(ver));
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, cap - bits.length));        // terminator
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) push(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));

  const size = sizeOf(ver);
  const mod = Array.from({ length: size }, () => new Uint8Array(size));
  const fn = Array.from({ length: size }, () => new Uint8Array(size));
  const set = (x, y, dark) => { mod[y][x] = dark ? 1 : 0; fn[y][x] = 1; };

  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  const al = alignPositions(ver), last = al.length - 1;
  for (let i = 0; i <= last; i++) {
    for (let j = 0; j <= last; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  const drawFormat = (mask) => {
    const f = formatBits(ecl, mask), bit = (i) => (f >>> i) & 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, 1);                          // the always-dark module
  };
  drawFormat(0);                                  // reserve the area
  if (ver >= 7) {
    const v = versionBits(ver);
    for (let i = 0; i < 18; i++) {
      const b = (v >>> i) & 1, a = size - 11 + (i % 3), c = Math.floor(i / 3);
      set(a, c, b); set(c, a, b);
    }
  }

  // Codewords zigzag up and down two-column strips from the bottom right.
  const cw = addEcc(data, ver, ecl);
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;                   // skip the vertical timing line
    const up = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j, y = up ? size - 1 - vert : vert;
        if (!fn[y][x] && i < cw.length * 8) { mod[y][x] = (cw[i >>> 3] >>> (7 - (i & 7))) & 1; i++; }
      }
    }
  }

  const applyMask = (k) => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[k](x, y)) mod[y][x] ^= 1;
  };
  let best = 0, bestScore = Infinity;
  for (let k = 0; k < 8; k++) {
    if (mask >= 0 && k !== mask) continue;
    applyMask(k); drawFormat(k);
    const s = penalty(mod);
    if (s < bestScore) { best = k; bestScore = s; }
    applyMask(k);                                 // XOR again = undo
  }
  applyMask(best); drawFormat(best);
  return { version: ver, size, ecl, mask: best, modules: mod, isFunction: fn };
}

module.exports = {
  encode, MAX_VERSION, ECC_PER_BLOCK, NUM_BLOCKS,
  rawCodewords, dataCodewords, alignPositions, rsDivisor, rsRemainder, formatBits, versionBits, ccBits,
};
