'use strict';
// Generates test/vectors.json INDEPENDENTLY of src/shared: straight from the
// DESIGN.md §4.3/§4.4 text using OpenSSL via node:crypto, so the KAT test is a
// cross-implementation check, not the code agreeing with itself.
const c = require('crypto');
const fs = require('fs');
const path = require('path');
const secret = Buffer.alloc(32).map((_, i) => 0x40 + i);
const chunks = [];
for (const [dir, index, isLast, plaintext] of [[1, 0, false, 'hello, guest'], [1, 7, true, ''], [2, 0, true, 'guest to host é']]) {
  const fileId = Buffer.alloc(16).map((_, i) => (i * 17 + dir) & 0xff);
  const key = Buffer.from(c.hkdfSync('sha256', secret, fileId, Buffer.concat([Buffer.from('transfer-file-v1'), Buffer.from([dir])]), 32));
  const hdr = Buffer.alloc(22); hdr[0] = 1; fileId.copy(hdr, 1); hdr.writeUInt32BE(index, 17); hdr[21] = isLast ? 1 : 0;
  const nonce = Buffer.alloc(12); nonce.writeBigUInt64BE(BigInt(index), 4);
  const ci = c.createCipheriv('aes-256-gcm', key, nonce); ci.setAAD(hdr);
  const ct = Buffer.concat([ci.update(Buffer.from(plaintext, 'utf8')), ci.final(), ci.getAuthTag()]);
  chunks.push({ dir, index, isLast, fileId: fileId.toString('base64url'), plaintext, frame: Buffer.concat([hdr, ct]).toString('hex') });
}
fs.writeFileSync(path.join(__dirname, '..', 'test', 'vectors.json'), JSON.stringify({ ikmHex: secret.toString('hex'), chunks }, null, 2) + '\n');
console.log('wrote', chunks.length, 'vectors');
