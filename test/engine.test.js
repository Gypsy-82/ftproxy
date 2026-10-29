'use strict';
// Protocol tests for the shared engine (DESIGN.md §5): two real Engines joined
// by an in-memory wire that the test can tamper with like a hostile TLS edge —
// flip, drop, replay, reflect, reorder, cut the connection mid-transfer.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const sc = require('../src/shared/stream-crypto');
const { Engine } = require('../src/shared/engine');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Every engine a test creates is destroyed afterwards, so no 120 s offer timer
// keeps the process alive (and no test leaks state into the next).
const live = [];
test.afterEach(() => { while (live.length) live.pop().destroy(); });

function memSink(log) {
  const s = { chunks: [], aborted: false, committed: false };
  s.write = async (i, u8) => { s.chunks[i] = Buffer.from(u8); };
  s.commit = async () => { s.committed = true; return Buffer.concat(s.chunks); };
  s.abort = () => { s.aborted = true; };
  log.push(s);
  return s;
}
function memSource(bytes, type, over = {}) {
  return {
    name: 'f' + ({ jpeg: '.jpg' }[type] || '.' + type), size: bytes.length, type,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'), stripped: false,
    read: async (i) => new Uint8Array(bytes.subarray(i * sc.CHUNK, i * sc.CHUNK + sc.expectedLen(bytes.length, i))),
    close() { this.closed = true; },
    ...over,
  };
}
const text = (n) => Buffer.from('x'.repeat(n));
const png = (n) => Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), crypto.randomBytes(n - 8)]);

// Both engines + a wire. `wire.tap(frame)` may return the frame, null (drop),
// or an array (inject). frame = { from, kind: 'text'|'bin', data }.
async function pair(opts = {}) {
  const secret = crypto.randomBytes(32);
  const base = await sc.importSecret(new Uint8Array(secret));
  const encKey = await globalThis.crypto.subtle.importKey('raw', crypto.randomBytes(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const wire = { tap: null, log: [], q: [], busy: false };
  const sinks = { host: [], guest: [] };
  const ev = { host: [], guest: [] };
  const eng = {};
  const deliver = () => {
    if (wire.busy) return; wire.busy = true;
    setImmediate(() => {
      wire.busy = false;
      while (wire.q.length) {
        const f = wire.q.shift();
        const to = eng[f.from === 'host' ? 'guest' : 'host'];
        if (f.kind === 'text') to.onText(JSON.parse(f.data)); else to.onBinary(f.data);
      }
    });
  };
  const send = (from, kind, data) => {
    const f = { from, kind, data };
    wire.log.push(f);
    let out = wire.tap ? wire.tap(f) : f;
    if (out == null) return;
    for (const g of [].concat(out)) wire.q.push(g);
    deliver();
  };
  for (const role of ['host', 'guest']) {
    eng[role] = new Engine({
      role, base, encKey, offerTtlMs: opts.offerTtlMs, resumeWaitMs: opts.resumeWaitMs,
      io: { sendText: (s) => send(role, 'text', s), sendBinary: async (u8) => { send(role, 'bin', new Uint8Array(u8)); return true; } },
      openSink: async () => memSink(sinks[role]),
      canAccept: opts.canAccept,
    });
    for (const e of ['offer', 'done', 'failed', 'tamper', 'strike', 'chat', 'state']) eng[role].on(e, (...a) => ev[role].push([e, ...a]));
    live.push(eng[role]);
  }
  const bind = new Uint8Array(crypto.randomBytes(48));
  await Promise.all([eng.host.connect(bind), eng.guest.connect(bind)]);
  const reconnect = async () => {
    await Promise.all([eng.host.disconnect(), eng.guest.disconnect()]);
    wire.q.length = 0;                              // whatever was in flight is lost
    const b = new Uint8Array(crypto.randomBytes(48));
    await Promise.all([eng.host.connect(b), eng.guest.connect(b)]);
  };
  const has = (role, name) => ev[role].find((x) => x[0] === name);
  const until = async (fn, ms = 3000) => { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await wait(5); } };
  return { eng, wire, sinks, ev, has, until, reconnect };
}

test('host -> guest: offer, accept, stream, verify, done on both sides', async () => {
  const p = await pair();
  const data = text(3 * sc.CHUNK + 123);
  await p.eng.host.offer(memSource(data, 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  assert.equal(p.has('guest', 'offer')[1].name, 'f.txt');
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'done') && p.has('host', 'done'));
  assert.ok(p.has('guest', 'done')[2].equals(data), 'bytes identical');
  assert.equal(p.sinks.guest[0].aborted, false);
});

test('guest -> host works the same way, and chat rides the envelope', async () => {
  const p = await pair();
  const data = png(sc.CHUNK * 2);
  await p.eng.guest.offer(memSource(data, 'png'));
  await p.until(() => p.has('host', 'offer'));
  await p.eng.host.accept();
  await p.eng.guest.chat('sending you the png now');
  await p.until(() => p.has('host', 'done') && p.has('host', 'chat'));
  assert.ok(p.has('host', 'done')[2].equals(data));
  assert.equal(p.has('host', 'chat')[1], 'sending you the png now');
  assert.ok(p.wire.log.every((f) => f.kind === 'bin' || !f.data.includes('sending you')), 'chat is never on the wire in clear');
});

test('both directions at once (one per direction)', async () => {
  const p = await pair();
  const a = text(sc.CHUNK * 3), b = png(sc.CHUNK * 3 + 5);
  await p.eng.host.offer(memSource(a, 'txt'));
  await p.eng.guest.offer(memSource(b, 'png'));
  await p.until(() => p.has('host', 'offer') && p.has('guest', 'offer'));
  await Promise.all([p.eng.host.accept(), p.eng.guest.accept()]);
  await p.until(() => p.ev.host.filter((x) => x[0] === 'done').length === 2 && p.ev.guest.filter((x) => x[0] === 'done').length === 2);
});

test('nothing moves before Accept; decline ends it cleanly', async () => {
  const p = await pair();
  await p.eng.host.offer(memSource(text(100), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  await wait(30);
  assert.equal(p.wire.log.filter((f) => f.kind === 'bin').length, 0, 'zero chunks sent before accept');
  await p.eng.guest.decline();
  await p.until(() => p.eng.host.out.state === 'declined');
});

test('an offer expires without accept', async () => {
  const p = await pair({ offerTtlMs: 60 });
  await p.eng.host.offer(memSource(text(100), 'txt'));
  await p.until(() => p.eng.host.out.state === 'declined' && p.eng.guest.inc.state === 'expired');
});

test('receiver refuses: busy, duplicate id, invalid fields, oversize', async () => {
  const p = await pair();
  await p.eng.host.offer(memSource(text(10), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  // force a second offer in the same direction (the honest engine refuses locally)
  await assert.rejects(p.eng.host.offer(memSource(text(10), 'txt')), /already/);
  const first = p.eng.host.out;
  p.eng.host.out = null;
  await p.eng.host.offer(memSource(text(10), 'txt'));
  await p.until(() => p.eng.host.out.state === 'declined');
  assert.equal(p.eng.host.out.reason, 'busy');
  p.eng.host.out = first;

  // replay an offer id the receiver already saw (sent fresh, under a valid seq)
  const lie = { op: 'offer', id: first.id, name: 'x.txt', size: 1, type: 'txt', sha256: 'a'.repeat(64) };
  const declined = [];
  p.wire.tap = (f) => { if (f.from === 'guest' && f.kind === 'text') declined.push(f); return f; };
  await p.eng.guest.decline();
  await p.eng.host._send(lie);
  for (const bad of [
    { ...lie, id: sc.toB64u(crypto.randomBytes(16)), size: sc.MAX_SIZE + 1 },
    { ...lie, id: sc.toB64u(crypto.randomBytes(16)), size: -1 },
    { ...lie, id: sc.toB64u(crypto.randomBytes(16)), type: 'svg' },
    { ...lie, id: sc.toB64u(crypto.randomBytes(16)), name: '...' },
    { ...lie, id: sc.toB64u(crypto.randomBytes(16)), sha256: 'zz' },
  ]) await p.eng.host._send(bad);
  await wait(60);
  const strikes = p.ev.guest.filter((x) => x[0] === 'strike').length;
  assert.equal(strikes, 5, 'each invalid offer is a strike');
  assert.equal(p.ev.guest.filter((x) => x[0] === 'offer').length, 1, 'none of them was shown to the user');
});

test('cancel mid-stream deletes the partial on the receiver', async () => {
  const p = await pair();
  let n = 0;
  p.wire.tap = (f) => { if (f.kind === 'bin' && ++n === 3) setImmediate(() => p.eng.host.cancel()); return f; };
  await p.eng.host.offer(memSource(text(sc.CHUNK * 40), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await p.until(() => p.eng.guest.inc.state === 'failed');
  assert.match(p.eng.guest.inc.reason, /cancelled by the other side/);
  assert.equal(p.sinks.guest[0].aborted, true, 'partial deleted');
  await wait(30);
  assert.equal(p.has('guest', 'tamper'), undefined, 'stray in-flight chunks after cancel are not tamper');
});

// ---------- the hostile edge ----------
async function streamWith(tap, size = sc.CHUNK * 6) {
  const p = await pair();
  await p.eng.host.offer(memSource(text(size), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  p.wire.tap = tap(p);
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'tamper') || p.has('host', 'tamper') || p.has('guest', 'done'));
  return p;
}
const nth = (n, fn) => () => { let i = 0; return (f) => (f.kind === 'bin' && ++i === n ? fn(f) : f); };

test('edge flips a bit in a chunk -> tamper, partial deleted', async () => {
  const p = await streamWith(nth(2, (f) => { const d = new Uint8Array(f.data); d[500] ^= 1; return { ...f, data: d }; }));
  assert.match(p.has('guest', 'tamper')[1], /authentication/);
  assert.equal(p.sinks.guest[0].aborted, true);
});
test('edge drops a chunk -> tamper', async () => {
  const p = await streamWith(nth(2, () => null));
  assert.match(p.has('guest', 'tamper')[1], /out of order/);
});
test('edge replays a chunk -> tamper', async () => {
  const p = await streamWith(nth(2, (f) => [f, f]));
  assert.match(p.has('guest', 'tamper')[1], /out of order/);
});
test('edge replays the last chunk after completion -> tamper (not silently ignored)', async () => {
  const p = await pair();
  let last = null;
  p.wire.tap = (f) => { if (f.kind === 'bin') last = f; return f; };
  await p.eng.host.offer(memSource(text(100), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'done'));
  p.eng.guest.onBinary(last.data);
  await p.until(() => p.has('guest', 'tamper'));
});
test('edge replays a control envelope -> tamper', async () => {
  const p = await pair();
  await p.eng.host.chat('one');
  await p.until(() => p.has('guest', 'chat'));
  const env = p.wire.log.find((f) => f.kind === 'text');
  p.eng.guest.onText(JSON.parse(env.data));
  await p.until(() => p.has('guest', 'tamper'));
  assert.match(p.has('guest', 'tamper')[1], /replayed/);
});
test('edge re-numbers a replayed envelope -> tamper (seq is inside the AAD)', async () => {
  const p = await pair();
  await p.eng.host.chat('one');
  await p.until(() => p.has('guest', 'chat'));
  const m = JSON.parse(p.wire.log.find((f) => f.kind === 'text').data);
  p.eng.guest.onText({ ...m, s: 2 });
  await p.until(() => p.has('guest', 'tamper'));
  assert.match(p.has('guest', 'tamper')[1], /authentication/);
});
test('edge REFLECTS the host\'s own envelope back at it -> tamper', async () => {
  const p = await pair();
  await p.eng.host.chat('hello');
  await p.until(() => p.has('guest', 'chat'));
  const m = JSON.parse(p.wire.log.find((f) => f.from === 'host').data);
  p.eng.host.onText(m);                              // host's own seq 1 arrives "from the guest"
  await p.until(() => p.has('host', 'tamper'));
  assert.equal(p.has('host', 'chat'), undefined, 'reflected message was never shown');
});
test('edge reorders two envelopes -> tamper', async () => {
  const p = await pair();
  const held = [];
  p.wire.tap = (f) => { if (f.kind === 'text') { held.push(f); return held.length === 2 ? [held[1], held[0]] : null; } return f; };
  await p.eng.host.chat('a');
  await p.eng.host.chat('b');
  await p.until(() => p.has('guest', 'tamper'));
});
test('envelopes from an OLD connection are useless on a new one', async () => {
  const p = await pair();
  await p.eng.host.chat('before');
  await p.until(() => p.has('guest', 'chat'));
  const old = JSON.parse(p.wire.log.find((f) => f.kind === 'text').data);
  await p.reconnect();
  p.eng.guest.onText(old);                           // seq 1 again, but the binding changed
  await p.until(() => p.has('guest', 'tamper'));
  assert.match(p.has('guest', 'tamper')[1], /authentication/);
});

// ---------- lying peer (authenticated, but dishonest) ----------
test('type mismatch: offer says pdf, bytes are png -> failed + strike, partial deleted', async () => {
  const p = await pair();
  await p.eng.host.offer(memSource(png(5000), 'pdf'));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'failed'));
  assert.match(p.has('guest', 'failed')[2], /not a valid PDF/);
  assert.ok(p.has('guest', 'strike'));
  assert.equal(p.sinks.guest[0].aborted, true);
  await p.until(() => p.eng.host.out.state === 'failed');
});
test('hash mismatch -> failed + strike', async () => {
  const p = await pair();
  await p.eng.host.offer(memSource(text(5000), 'txt', { sha256: 'b'.repeat(64) }));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'failed'));
  assert.match(p.has('guest', 'failed')[2], /hash mismatch/);
  assert.equal(p.sinks.guest[0].committed, false, 'never committed');
});
test('stream overruns a lying offer -> failed at the stream, not just at the offer', async () => {
  const p = await pair();
  const real = text(sc.CHUNK * 3);
  await p.eng.host.offer(memSource(real.subarray(0, 100), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  Object.assign(p.eng.host.out, { size: real.length, total: 3, src: memSource(real, 'txt') });   // now lie
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'failed'));
  assert.match(p.has('guest', 'failed')[2], /stream length/);
  assert.equal(p.sinks.guest[0].aborted, true);
});

// ---------- resume (§5.4) ----------
test('connection drops mid-transfer -> reconnect resumes from `next`, hash OK', async () => {
  const p = await pair();
  const data = text(sc.CHUNK * 30 + 7);
  let n = 0, cut = false;
  p.wire.tap = (f) => {
    if (f.kind === 'bin' && ++n === 11 && !cut) { cut = true; setImmediate(() => p.reconnect()); return null; }
    return f;
  };
  await p.eng.host.offer(memSource(data, 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await p.until(() => p.has('guest', 'done') || p.has('guest', 'tamper') || p.has('guest', 'failed'), 5000);
  assert.ok(cut, 'the connection was actually cut');
  assert.ok(p.has('guest', 'done'), 'transfer completed after resume');
  assert.ok(p.has('guest', 'done')[2].equals(data), 'bytes identical after resume');
  const resumed = p.ev.guest.filter((x) => x[0] === 'state' && x[1].state === 'paused').length;
  assert.ok(resumed >= 1, 'went through PAUSED');
});

test('sender gives up if the receiver never resumes', async () => {
  const p = await pair({ resumeWaitMs: 50 });
  let n = 0;
  p.wire.tap = (f) => (f.kind === 'bin' && ++n >= 3 ? null : f);
  await p.eng.host.offer(memSource(text(sc.CHUNK * 20), 'txt'));
  await p.until(() => p.has('guest', 'offer'));
  await p.eng.guest.accept();
  await wait(30);
  p.eng.guest.inc.state = 'failed';                  // simulate a guest that lost its state (reload)
  await p.reconnect();
  await p.until(() => p.eng.host.out.state === 'failed');
  assert.match(p.eng.host.out.reason, /did not resume/);
});
