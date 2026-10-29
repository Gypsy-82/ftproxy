'use strict';
// Host-side file source for /send (DESIGN.md §9). Produces the engine's
// source interface: { name, size, type, sha256, stripped, warn, read(i), close() }.
//
//   * lstat first: must be a regular file — no symlink, dir, device or FIFO.
//   * open O_NOFOLLOW, then fstat the fd and require the SAME dev/inode as the
//     lstat. That closes the check-then-open race where the path is swapped
//     for a symlink to ~/.ssh/id_ed25519 between the two calls.
//   * Type from magic bytes (and a full-file pass for txt), never the extension.
//   * JPEG metadata stripped into memory before hashing, unless --keep-meta.
//   * Hash first, then offer. Every read re-fstats: if size/mtime moved, the
//     file changed under us and the send is cancelled.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const sc = require('./shared/stream-crypto');
const ft = require('./shared/filetype');
const exif = require('./shared/exif');
const { cleanName } = require('./shared/names');

function expandHome(p) {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

async function readExact(fh, len, pos) {
  const buf = Buffer.alloc(len);
  let off = 0;
  while (off < len) {
    const { bytesRead } = await fh.read(buf, off, len - off, pos + off);
    if (!bytesRead) throw new Error('file changed while reading (got shorter)');
    off += bytesRead;
  }
  return new Uint8Array(buf.buffer, buf.byteOffset, len);
}

async function openHostSource(rawPath, { keepMeta = false } = {}) {
  const abs = path.resolve(expandHome(String(rawPath)));
  let st;
  try { st = await fs.promises.lstat(abs); } catch (e) { throw new Error(e.code === 'ENOENT' ? 'no such file' : e.message); }
  if (st.isSymbolicLink()) throw new Error('that path is a symlink — refusing; pass the real file');
  if (!st.isFile()) throw new Error('not a regular file');
  if (st.size > sc.MAX_SIZE) throw new Error('too large — the limit is 500 MiB');

  const fh = await fs.promises.open(abs, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const fst = await fh.stat();
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) throw new Error('file was swapped while opening — refusing');
    if (fst.size > sc.MAX_SIZE) throw new Error('too large — the limit is 500 MiB');

    const head = fst.size ? await readExact(fh, Math.min(fst.size, ft.PDF_WINDOW), 0) : new Uint8Array(0);
    const type = ft.sniff(head);
    let mem = null, stripped = false, warn = '';
    if (type === 'jpeg' && !keepMeta) {
      if (fst.size <= exif.STRIP_LIMIT) {
        const whole = await readExact(fh, fst.size, 0);
        let r;
        try { r = exif.strip(whole); }
        catch (e) { throw new Error(e.message + ' — metadata cannot be stripped safely; use /send --keep-meta to send it as-is'); }
        mem = r.bytes; stripped = true;
        if (r.removed) warn = `removed ${r.removed} bytes of photo metadata (location, camera, timestamps)`;
      } else {
        warn = 'JPEG is over 50 MiB: sent WITH its metadata (may include location)';
      }
    }
    const size = mem ? mem.length : fst.size;
    const total = sc.totalChunks(size);

    const read = async (i) => {
      const len = sc.expectedLen(size, i);
      if (mem) return mem.subarray(i * sc.CHUNK, i * sc.CHUNK + len);
      const now = await fh.stat();
      if (now.size !== fst.size || now.mtimeMs !== fst.mtimeMs) throw new Error('file changed while sending');
      return readExact(fh, len, i * sc.CHUNK);
    };

    // Hash + full validation pass BEFORE offering: the receiver will run the
    // same validator, so failing here just fails early with a better message.
    const v = ft.validator(type);
    const h = crypto.createHash('sha256');
    for (let i = 0; i < total; i++) {
      const b = await read(i);
      try { v.push(b); } catch (e) { throw new Error(type === 'txt' ? 'not an allowed type (txt, png, jpg, mp4, pdf)' : e.message); }
      h.update(b);
    }
    try { v.finish(); } catch { throw new Error('not an allowed type (txt, png, jpg, mp4, pdf)'); }

    const name = cleanName(path.basename(abs), type) || 'file' + ft.EXT[type];
    let closed = false;
    return {
      path: abs, name, size, type, sha256: h.digest('hex'), stripped, warn,
      read,
      close() { if (!closed) { closed = true; fh.close().catch(() => {}); } },
    };
  } catch (e) {
    await fh.close().catch(() => {});
    throw e;
  }
}

// Node's hasher for the engine — same { update, hex } shape as shared/sha256.
function nodeHasher() {
  const h = crypto.createHash('sha256');
  return { update(b) { h.update(b); }, hex() { return h.digest('hex'); } };
}

module.exports = { openHostSource, nodeHasher, expandHome };
