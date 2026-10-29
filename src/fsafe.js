'use strict';
// Quarantine inbox for files arriving from the guest (DESIGN.md §8).
//
// Everything written here is attacker-supplied bytes under an attacker-
// influenced name, so the rules are strict and boring:
//   * The inbox must be a real directory we own, not writable by group/other
//     (otherwise another local user could race us with symlinks). Created 0700.
//   * Partials go to `.<random>.part`, opened O_CREAT|O_EXCL|O_NOFOLLOW, 0600.
//     EXCL means we never open something that already exists; NOFOLLOW means a
//     planted symlink can't redirect the write.
//   * Final name: `<YYYYMMDD-HHMMSS>-<cleanName>`, reserved with an O_EXCL
//     placeholder and then rename()d over it. No check-then-write race, and
//     rename never follows a symlink at the destination.
//   * Never auto-opened, previewed or cat'd. The TUI prints path + size + hash.
//   * Partials are unlinked on fail/cancel/burn, and swept at startup.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { promisify } = require('util');
const crypto = require('crypto');
const { EXT } = require('./shared/filetype');
const { CHUNK } = require('./shared/stream-crypto');

const fsWrite = promisify(fs.write);
const fsFsync = promisify(fs.fsync);
const { O_CREAT, O_EXCL, O_WRONLY, O_NOFOLLOW } = fs.constants;
const NEW_FILE = O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW;
const HEADROOM = 64 * 1024 * 1024;
const PART_RE = /^\.[A-Za-z0-9_-]{22}\.part$/;

function defaultInbox() { return path.join(os.homedir(), 'Downloads', 'ftproxy-inbox'); }

function stamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

class Inbox {
  constructor(dir = defaultInbox()) {
    this.dir = path.resolve(dir);
    this._ensure();
  }

  _ensure() {
    let st;
    try { st = fs.lstatSync(this.dir); }
    catch (e) {
      if (e.code !== 'ENOENT') throw e;
      fs.mkdirSync(path.dirname(this.dir), { recursive: true });
      fs.mkdirSync(this.dir, { mode: 0o700 });
      st = fs.lstatSync(this.dir);
    }
    if (st.isSymbolicLink()) throw new Error(`inbox ${this.dir} is a symlink — refusing (point --inbox at a real directory)`);
    if (!st.isDirectory()) throw new Error(`inbox ${this.dir} is not a directory`);
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new Error(`inbox ${this.dir} is owned by another user`);
    if (st.mode & 0o022) throw new Error(`inbox ${this.dir} is group/world-writable — run: chmod 700 '${this.dir}'`);
  }

  // Remove partials left behind by a crash. Only our own regular files.
  sweep() {
    let n = 0;
    for (const name of fs.readdirSync(this.dir)) {
      if (!PART_RE.test(name)) continue;
      const p = path.join(this.dir, name);
      try {
        const st = fs.lstatSync(p);
        if (st.isFile() && (typeof process.getuid !== 'function' || st.uid === process.getuid())) { fs.unlinkSync(p); n++; }
      } catch {}
    }
    return n;
  }

  // null if there's room, else a human reason (sent to the peer as the decline reason).
  checkSpace(size) {
    try {
      const s = fs.statfsSync(this.dir);
      const free = s.bavail * s.bsize;
      if (free < size + HEADROOM) return 'receiver is low on disk space';
    } catch { return 'receiver could not check disk space'; }
    return null;
  }

  // An engine sink for one incoming file. view = engine transfer view.
  open(view) {
    this._ensure();                                   // re-check: perms could have changed since launch
    const partName = '.' + crypto.randomBytes(16).toString('base64url') + '.part';
    const partPath = path.join(this.dir, partName);
    const fd = fs.openSync(partPath, NEW_FILE, 0o600);
    let open = true;
    const inbox = this;
    return {
      partPath,
      async write(index, bytes) {
        let off = 0;
        while (off < bytes.length) {
          const n = await fsWrite(fd, bytes, off, bytes.length - off, index * CHUNK + off);
          off += n;
        }
      },
      async commit() {
        await fsFsync(fd);
        fs.closeSync(fd); open = false;
        const final = inbox._reserve(view.name, view.type);
        fs.renameSync(partPath, final);
        return final;
      },
      abort() {                                        // sync on purpose: runs during process exit
        if (open) { try { fs.closeSync(fd); } catch {} open = false; }
        try { fs.unlinkSync(partPath); } catch {}
      },
    };
  }

  // Claim a free final name atomically with O_EXCL; -1, -2… on a clash.
  _reserve(cleanName, type) {
    const ext = EXT[type];
    const base = `${stamp()}-${cleanName.slice(0, cleanName.length - ext.length)}`;
    for (let n = 0; n < 1000; n++) {
      const p = path.join(this.dir, base + (n ? `-${n}` : '') + ext);
      try { fs.closeSync(fs.openSync(p, NEW_FILE, 0o600)); return p; }
      catch (e) { if (e.code !== 'EEXIST') throw e; }
    }
    throw new Error('could not find a free filename');
  }
}

module.exports = { Inbox, defaultInbox, stamp, PART_RE, HEADROOM };
