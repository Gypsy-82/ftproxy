// Incremental SHA-256 (FIPS 180-4). WebCrypto has no streaming digest, and a
// 500 MiB file can't be hashed with one subtle.digest() call without holding it
// all in memory, so the browser uses this. Node passes crypto.createHash instead
// (faster); test/sha256.test.js proves the two agree byte for byte.
//
// ISOMORPHIC: this file runs unmodified in Node (require) AND is inlined
// verbatim into the guest page by src/page.js. Uint8Array only — no Buffer.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('sha256', function () {
  'use strict';

  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  class Sha256 {
    constructor() {
      this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
      this.w = new Uint32Array(64);
      this.buf = new Uint8Array(64);
      this.bufLen = 0;
      this.len = 0;        // total bytes; a JS number is exact far past 500 MiB
      this.finished = false;
    }

    update(data) {
      if (this.finished) throw new Error('sha256: update after digest');
      const n = data.length;
      let i = 0;
      this.len += n;
      if (this.bufLen) {
        const take = Math.min(64 - this.bufLen, n);
        this.buf.set(data.subarray(0, take), this.bufLen);
        this.bufLen += take;
        i = take;
        if (this.bufLen < 64) return this;
        this._block(this.buf, 0);
        this.bufLen = 0;
      }
      for (; i + 64 <= n; i += 64) this._block(data, i);
      if (i < n) { this.buf.set(data.subarray(i), 0); this.bufLen = n - i; }
      return this;
    }

    _block(d, o) {
      const w = this.w, h = this.h;
      for (let t = 0; t < 16; t++, o += 4) w[t] = (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
      for (let t = 16; t < 64; t++) {
        const x = w[t - 15], y = w[t - 2];
        const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      let a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (let t = 0; t < 64; t++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (dd + t1) | 0; dd = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    digest() {
      if (this.finished) throw new Error('sha256: digest called twice');
      const bitsHi = Math.floor(this.len / 0x20000000);   // len * 8 split into two 32-bit words
      const bitsLo = (this.len * 8) >>> 0;
      const b = this.buf;
      b[this.bufLen++] = 0x80;
      if (this.bufLen > 56) { b.fill(0, this.bufLen); this._block(b, 0); this.bufLen = 0; }
      b.fill(0, this.bufLen, 56);
      b[56] = bitsHi >>> 24; b[57] = bitsHi >>> 16; b[58] = bitsHi >>> 8; b[59] = bitsHi;
      b[60] = bitsLo >>> 24; b[61] = bitsLo >>> 16; b[62] = bitsLo >>> 8; b[63] = bitsLo;
      this._block(b, 0);
      this.finished = true;
      const out = new Uint8Array(32);
      for (let i = 0; i < 8; i++) {
        out[4 * i] = this.h[i] >>> 24; out[4 * i + 1] = this.h[i] >>> 16;
        out[4 * i + 2] = this.h[i] >>> 8; out[4 * i + 3] = this.h[i];
      }
      return out;
    }

    hex() {
      const d = this.digest();
      let s = '';
      for (let i = 0; i < d.length; i++) s += d[i].toString(16).padStart(2, '0');
      return s;
    }
  }

  // The engine's hasher interface: { update(u8), hex() }.
  function create() { return new Sha256(); }

  return { Sha256, create };
});
