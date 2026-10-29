'use strict';
// Full stack: real Relay (wslite) + host engine + on-disk Inbox, against a
// guest that is the `ws` library running the SAME shared engine the browser
// page runs. Also checks the inherited SMSproxy guarantees still hold.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');
const c = require('../src/crypto');
const sc = require('../src/shared/stream-crypto');
const { Engine } = require('../src/shared/engine');
const { Relay } = require('../src/server');
const { Inbox, PART_RE } = require('../src/fsafe');
const { createHostEngine, sendPath } = require('../src/transfer');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 10000) => { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await wait(10); } };
const cleanup = [];
test.afterEach(() => { while (cleanup.length) { try { cleanup.pop()(); } catch {} } });

function httpGet(port, p, headers = {}) {
  return new Promise((res) => {
    http.get({ host: '127.0.0.1', port, path: p, headers }, (r) => {
      let b = ''; r.on('data', (d) => (b += d)); r.on('end', () => res({ status: r.statusCode, headers: r.headers, body: b }));
    }).on('error', () => res({ status: 0, headers: {}, body: '' }));
  });
}

async function host(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-e2e-'));
  const secret = c.newSessionKey();
  const salt = c.randomB64u(16);
  const keys = await c.deriveKeys(secret, salt);
  const token = c.randomB64u(24);
  const relay = new Relay({ token, salt, keys, port: 0, maxFails: opts.maxFails || 10, burnOnDisconnect: true, graceSec: opts.graceSec ?? 30, heartbeatSec: opts.heartbeatSec ?? 15 });
  const inbox = new Inbox(path.join(dir, 'inbox'));
  const engine = await createHostEngine({ relay, secret: c.fromB64u(secret), encKey: keys.encKey, inbox });
  const port = await relay.listen();
  const ev = [];
  for (const e of ['offer', 'done', 'failed', 'chat']) engine.on(e, (...a) => ev.push([e, ...a]));
  for (const e of ['tamper', 'selfdestruct', 'transfer-strike']) relay.on(e, (...a) => ev.push([e, ...a]));
  cleanup.push(() => { engine.destroy(); relay.destroy(); fs.rmSync(dir, { recursive: true, force: true }); });
  return { relay, engine, inbox, dir, secret, port, ev, wsUrl: `ws://127.0.0.1:${port}/r/${token}/ws`, base: `/r/${token}`, has: (n) => ev.find((x) => x[0] === n) };
}

// A guest that behaves exactly like public/index.html's glue.
// `link` is the one mutable socket slot the engine's io writes to — like the
// page's module-level `ws`, reassigned on every reconnect.
function guest(url, secret, { ticket, sinks = [], engine: existing, link = {}, origin, noPong = false } = {}) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, origin ? { origin } : {});
    link.ws = ws;
    const g = { ws, link, authed: false, busy: false, authFail: false, tampered: false, ev: [], sinks, engine: existing, reconnect: '' };
    let challenge, cn;
    ws.on('message', async (buf, isBinary) => {
      if (isBinary) return g.engine && g.engine.onBinary(new Uint8Array(buf));
      const m = JSON.parse(buf.toString());
      if (m.t === 'x') return g.engine && g.engine.onText(m);
      if (m.t === 'ping') { g.pings = (g.pings || 0) + 1; if (!noPong) ws.send('{"t":"pong"}'); return; }
      if (m.t === 'hello') {
        g.keys = await c.deriveKeys(secret, m.salt);
        challenge = c.fromB64u(m.challenge); cn = sc.randomBytes(16);
        const msg = { t: 'auth', proof: c.toB64u(await c.sign(g.keys.macKey, challenge)), cn: sc.toB64u(cn) };
        if (ticket) msg.reconnect = ticket;
        ws.send(JSON.stringify(msg));
      } else if (m.t === 'auth-ok') {
        g.authed = true; g.reconnect = m.reconnect;
        if (!g.engine) {
          g.engine = new Engine({
            role: 'guest', base: await sc.importSecret(c.fromB64u(secret)), encKey: g.keys.encKey,
            io: { sendText: (s) => link.ws.readyState === 1 && link.ws.send(s), sendBinary: async (u8) => { if (link.ws.readyState !== 1) return false; link.ws.send(u8); return true; } },
            openSink: async () => { const s = { parts: [], aborted: false }; s.write = async (i, u) => { s.parts[i] = Buffer.from(u); }; s.commit = async () => Buffer.concat(s.parts); s.abort = () => { s.aborted = true; }; sinks.push(s); return s; },
          });
          for (const e of ['offer', 'done', 'failed', 'chat', 'tamper']) g.engine.on(e, (...a) => g.ev.push([e, ...a]));
        }
        g.engine.connect(sc.concat(challenge, cn));
        resolve(g);
      } else if (m.t === 'auth-fail') { g.authFail = true; resolve(g); }
      else if (m.t === 'busy') { g.busy = true; resolve(g); }
      else if (m.t === 'tamper') { g.tampered = true; }
    });
    ws.on('close', () => { if (g.engine && g.authed) g.engine.disconnect(); if (!g.authed && !g.authFail && !g.busy) resolve(g); });
    ws.on('error', () => {});
  });
}
const has = (g, n) => g.ev.find((x) => x[0] === n);

function genSource(size, type, fill) {
  const h = crypto.createHash('sha256');
  const chunk = (i) => { const b = Buffer.alloc(sc.expectedLen(size, i), fill); if (type === 'png' && i === 0) Buffer.from('89504e470d0a1a0a', 'hex').copy(b); return b; };
  for (let i = 0; i < sc.totalChunks(size); i++) h.update(chunk(i));
  return { name: 'big.' + type, size, type, sha256: h.digest('hex'), stripped: false, read: async (i) => new Uint8Array(chunk(i)), close() {} };
}

// ---------------- inherited surface ----------------
test('page is served with a strict, hash-pinned CSP; other paths 404', async () => {
  const h = await host();
  const ok = await httpGet(h.port, h.base, { host: 'abc.trycloudflare.com' });
  assert.equal(ok.status, 200);
  const csp = ok.headers['content-security-policy'];
  assert.match(csp, /script-src 'sha256-[A-Za-z0-9+/=]+'/);
  assert.ok(!csp.includes('unsafe-inline'), 'no unsafe-inline anywhere');
  assert.match(csp, /connect-src 'self' wss:\/\/abc\.trycloudflare\.com/);
  assert.ok(!/connect-src[^;]*wss: /.test(csp), 'no wildcard wss:');
  assert.equal(ok.headers['referrer-policy'], 'no-referrer');
  const evil = await httpGet(h.port, h.base, { host: 'x"; script-src *' });
  assert.ok(!/script-src \*/.test(evil.headers['content-security-policy']), 'a hostile Host header cannot widen the CSP');
  assert.equal((await httpGet(h.port, '/etc/passwd')).status, 404);
  assert.equal((await httpGet(h.port, `/r/${c.randomB64u(24)}`)).status, 404);
});

test('wrong key rejected; second guest refused; cross-site Origin refused', async () => {
  const h = await host();
  const bad = await guest(h.wsUrl, c.newSessionKey());
  assert.ok(bad.authFail);
  const cross = await guest(h.wsUrl, h.secret, { origin: 'https://evil.example' });
  assert.equal(cross.authed, false, 'cross-origin upgrade never authenticates');
  const g = await guest(h.wsUrl, h.secret, { origin: `http://127.0.0.1:${h.port}` });
  assert.ok(g.authed, 'same-origin works');
  const g2 = await guest(h.wsUrl, h.secret);
  assert.ok(g2.busy);
});

test('binary frames before auth get the socket closed (1008)', async () => {
  const h = await host();
  const ws = new WebSocket(h.wsUrl);
  const code = await new Promise((res) => {
    ws.on('message', () => ws.send(Buffer.alloc(40)));
    ws.on('close', (c2) => res(c2));
  });
  assert.equal(code, 1008);
});

// ---------------- transfers ----------------
test('host -> guest: real file from disk, guest receives identical bytes', async () => {
  const h = await host();
  const g = await guest(h.wsUrl, h.secret);
  const file = path.join(h.dir, 'report.pdf');
  const data = Buffer.concat([Buffer.from('%PDF-1.7\n'), crypto.randomBytes(200000)]);
  fs.writeFileSync(file, data);
  await sendPath(h.engine, file, {});
  await until(() => has(g, 'offer'));
  assert.equal(has(g, 'offer')[1].name, 'report.pdf');
  await g.engine.accept();
  await until(() => has(g, 'done') && h.has('done'));
  assert.ok(has(g, 'done')[2].equals(data));
});

test('guest -> host: lands in the inbox, 0600, timestamped, no partials left', async () => {
  const h = await host();
  const g = await guest(h.wsUrl, h.secret);
  await g.engine.offer(genSource(3 * sc.CHUNK + 9, 'png', 7));
  await until(() => h.has('offer'));
  await h.engine.accept();
  await until(() => h.has('done'));
  const saved = h.has('done')[2];
  assert.equal(path.dirname(saved), h.inbox.dir);
  assert.match(path.basename(saved), /^\d{8}-\d{6}-big\.png$/);
  assert.equal(fs.statSync(saved).mode & 0o777, 0o600);
  assert.equal(fs.readdirSync(h.inbox.dir).filter((n) => PART_RE.test(n)).length, 0);
});

test('guest lies about type -> host deletes the partial and counts a strike', async () => {
  const h = await host();
  const g = await guest(h.wsUrl, h.secret);
  const src = genSource(100000, 'png', 1);
  await g.engine.offer({ ...src, type: 'pdf', name: 'totally.pdf' });
  await until(() => h.has('offer'));
  await h.engine.accept();
  await until(() => h.has('failed'));
  assert.ok(h.has('transfer-strike'));
  assert.equal(fs.readdirSync(h.inbox.dir).length, 0, 'nothing left in the inbox');
});

test('edge injects a forged chunk -> both sides tamper, link burns, partial deleted', async () => {
  const h = await host();
  const g = await guest(h.wsUrl, h.secret);
  await g.engine.offer(genSource(20 * sc.CHUNK, 'txt', 0x61));
  await until(() => h.has('offer'));
  await h.engine.accept();
  await until(() => h.engine.inc.state === 'streaming' && h.engine.inc.next > 0);
  const forged = new Uint8Array(sc.HDR + 100); forged[0] = 1;
  forged.set(sc.fromB64u(h.engine.inc.id), 1);
  const idx = h.engine.inc.next + 1;                   // whatever comes next, this cannot authenticate
  forged[17] = idx >>> 24; forged[18] = idx >>> 16; forged[19] = idx >>> 8; forged[20] = idx;
  g.ws.send(forged);
  await until(() => h.has('tamper') && h.has('selfdestruct'));
  assert.match(h.has('selfdestruct')[1], /KEYS CHANGED/);
  await until(() => g.tampered);
  assert.equal(fs.readdirSync(h.inbox.dir).length, 0, 'partial deleted on burn');
});

test('kill the socket mid-transfer -> guest reconnects with its ticket -> resumes -> hash OK', async () => {
  const h = await host();
  const sinks = [];
  let g = await guest(h.wsUrl, h.secret, { sinks });
  const size = 120 * sc.CHUNK + 333;
  const file = path.join(h.dir, 'notes.txt');
  fs.writeFileSync(file, Buffer.alloc(size, 0x62));
  await sendPath(h.engine, file, {});
  await until(() => has(g, 'offer'));
  await g.engine.accept();
  await until(() => g.engine.inc.next >= 20);
  g.ws.terminate();                                     // abrupt, mid-stream
  await until(() => h.engine.out.state === 'paused');
  const g2 = await guest(h.wsUrl, h.secret, { ticket: g.reconnect, sinks, engine: g.engine, link: g.link });
  assert.ok(g2.authed, 'reclaimed the seat with the ticket');
  await until(() => has(g, 'done'), 15000);
  assert.ok(has(g, 'done')[2].equals(Buffer.alloc(size, 0x62)), 'identical after resume');
  assert.equal(h.has('selfdestruct'), undefined, 'no burn');
});

test('500 MiB exactly passes guest -> host; 500 MiB + 1 is refused at the offer', { timeout: 300000 }, async () => {
  const h = await host();
  const g = await guest(h.wsUrl, h.secret);
  await assert.rejects(g.engine.offer(genSource(sc.MAX_SIZE + 1, 'txt', 0x61)), /allowed type\/size/, 'honest engine refuses locally');
  // ...and a hostile guest that skips that check is refused by the receiver:
  await g.engine._send({ op: 'offer', id: sc.toB64u(sc.randomBytes(16)), name: 'x.txt', size: sc.MAX_SIZE + 1, type: 'txt', sha256: 'a'.repeat(64) });
  await until(() => h.has('transfer-strike'));
  assert.equal(h.has('offer'), undefined, 'oversize offer never shown');

  const t0 = Date.now();
  await g.engine.offer(genSource(sc.MAX_SIZE, 'txt', 0x61));
  await until(() => h.has('offer'));
  await h.engine.accept();
  await until(() => h.has('done') || h.has('failed'), 280000);
  assert.ok(h.has('done'), 'completed: ' + JSON.stringify(h.has('failed') || ''));
  const saved = h.has('done')[2];
  assert.equal(fs.statSync(saved).size, sc.MAX_SIZE);
  const secs = (Date.now() - t0) / 1000;
  console.log(`    # 500 MiB over loopback in ${secs.toFixed(1)}s (${(500 / secs).toFixed(0)} MiB/s incl. hashing)`);
});

// ---------------- guest leaving ----------------

test('guest sends bye (closed the page) -> burns at once, no grace wait', async () => {
  const h = await host({ graceSec: 30 });
  const g = await guest(h.wsUrl, h.secret);
  assert.ok(g.authed);
  const t0 = Date.now();
  g.ws.send('{"t":"bye"}');
  await until(() => h.has('selfdestruct'), 2000);
  assert.equal(h.has('selfdestruct')[1], 'the guest closed the page');
  assert.ok(Date.now() - t0 < 2000, 'did not wait out the 30 s grace');
});

test('bye before auth is ignored', async () => {
  const h = await host({ graceSec: 30 });
  const ws = new WebSocket(h.wsUrl);
  await new Promise((r) => ws.on('message', r));      // hello
  ws.send('{"t":"bye"}');
  await wait(200);
  assert.ok(!h.has('selfdestruct'), 'an unauthenticated socket cannot end the session');
  ws.close();
});

test('heartbeat: a guest that answers stays connected', async () => {
  const h = await host({ heartbeatSec: 0.1 });
  const g = await guest(h.wsUrl, h.secret);
  await wait(700);
  assert.ok(g.pings >= 3, 'pings arrive');
  assert.ok(h.relay.hasClient());
  assert.ok(!h.has('selfdestruct'));
});

test('heartbeat: a guest that goes silent is cut, then the link burns after grace', async () => {
  const h = await host({ heartbeatSec: 0.1, graceSec: 0.3 });
  const g = await guest(h.wsUrl, h.secret, { noPong: true });
  assert.ok(g.authed);
  await until(() => !h.relay.hasClient(), 3000);
  await until(() => h.has('selfdestruct'), 3000);
  assert.equal(h.has('selfdestruct')[1], 'client left');
});
