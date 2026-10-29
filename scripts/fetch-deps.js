#!/usr/bin/env node
'use strict';
// Downloads the helper binaries ftproxy needs (caddy for TLS/reverse-proxy,
// cloudflared for the public tunnel) for THIS platform into ./vendor/.
// Run by install.sh, and by the launcher on first run if one is missing.
//
// Versions are PINNED and every download is checked against the SHA-256 below
// before it is unpacked or made executable. A mismatch is refused. To upgrade,
// change the version and the hashes together (hashes come from the publisher's
// GitHub release asset digests), then run ./install.sh again.
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const OS = 'linux';                                             // Linux only
const ARCH = process.arch === 'arm64' ? 'arm64' : 'amd64';     // x64 -> amd64
const VENDOR = path.join(__dirname, '..', 'vendor');

const CADDY_V = '2.11.7';
const CLOUDFLARED_V = '2026.10.0';
const PINS = {
  caddy: {
    'linux-amd64': ['caddy_' + CADDY_V + '_linux_amd64.tar.gz', '727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b'],
    'linux-arm64': ['caddy_' + CADDY_V + '_linux_arm64.tar.gz', 'd8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42'],
    url: (f) => `https://github.com/caddyserver/caddy/releases/download/v${CADDY_V}/${f}`,
  },
  cloudflared: {
    'linux-amd64': ['cloudflared-linux-amd64', 'd33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db'],
    'linux-arm64': ['cloudflared-linux-arm64', 'e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08'],
    url: (f) => `https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_V}/${f}`,
  },
};

function isExec(p) { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } }

// Streams to dest while hashing; resolves with the hex SHA-256 of what landed.
function download(url, dest) {
  return new Promise((resolve, reject) => {
    (function get(u, n) {
      if (n > 8) return reject(new Error('too many redirects'));
      const req = https.get(u, { headers: { 'User-Agent': 'ftproxy-installer' }, timeout: 30000 }, (r) => {
        if ([301, 302, 303, 307, 308].includes(r.statusCode)) { r.resume(); return get(new URL(r.headers.location, u).href, n + 1); }
        if (r.statusCode !== 200) { r.resume(); return reject(new Error('HTTP ' + r.statusCode)); }
        const h = crypto.createHash('sha256');
        const f = fs.createWriteStream(dest, { mode: 0o600 });
        r.on('data', (b) => h.update(b));
        r.on('aborted', () => reject(new Error('download interrupted')));
        r.on('error', reject);
        r.pipe(f);
        f.on('finish', () => f.close(() => resolve(h.digest('hex'))));
        f.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('network timed out')));
      req.on('error', reject);
    })(url, 0);
  });
}

async function fetchTool(name) {
  const dest = path.join(VENDOR, name);
  const stamp = dest + '.sha256';
  const pin = PINS[name][OS + '-' + ARCH];
  if (!pin) throw new Error(`no pinned build for ${OS}/${ARCH}`);
  const [file, want] = pin;
  // The stamp records which verified archive produced this binary, so a pin
  // bump (or a binary that came from somewhere else) triggers a fresh fetch.
  let have = '';
  try { have = fs.readFileSync(stamp, 'utf8').trim(); } catch {}
  if (isExec(dest) && have === want) return console.log(`  ${name.padEnd(12)} already present (verified)`);

  process.stdout.write(`  ${name.padEnd(12)} downloading ${file} ... `);
  const part = path.join(VENDOR, file + '.part');
  try {
    const got = await download(PINS[name].url(file), part);
    if (got !== want) throw new Error(`CHECKSUM MISMATCH, refusing to install\n    expected ${want}\n    got      ${got}`);
    const tmp = dest + '.new';
    if (file.endsWith('.tar.gz')) {
      const dir = fs.mkdtempSync(path.join(VENDOR, '.x-'));
      try {
        const r = spawnSync('tar', ['-xzf', part, '-C', dir, name], { stdio: 'ignore' });
        if (r.status !== 0) throw new Error('could not unpack ' + file + ' (is tar installed?)');
        fs.renameSync(path.join(dir, name), tmp);
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    } else {
      fs.renameSync(part, tmp);
    }
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, dest);
    fs.writeFileSync(stamp, want + '\n');
    console.log('ok, checksum verified');
  } finally { fs.rmSync(part, { force: true }); }
}

(async () => {
  if (process.platform !== 'linux') { console.error('\n  ftproxy runs on Linux and Android (Termux) only.'); process.exit(1); }
  // Android can't run these desktop builds; Termux gets them from pkg instead.
  if ((process.env.PREFIX || '').includes('com.termux')) {
    console.error('\n  On Android (Termux), install the helpers with:  pkg install caddy cloudflared');
    process.exit(1);
  }
  fs.mkdirSync(VENDOR, { recursive: true });
  console.log(`\nFetching helpers for ${OS}/${ARCH} into vendor/`);
  let bad = 0;
  try { await fetchTool('caddy'); } catch (e) { bad++; console.error('FAILED\n    ' + e.message); }
  try { await fetchTool('cloudflared'); } catch (e) { bad++; console.error('FAILED\n    ' + e.message); }
  const okC = isExec(path.join(VENDOR, 'caddy'));
  const okT = isExec(path.join(VENDOR, 'cloudflared'));
  console.log(`\n  result: caddy ${okC ? 'ok' : 'MISSING'}   cloudflared ${okT ? 'ok' : 'MISSING'}`);
  process.exit(bad ? 1 : 0);
})();
