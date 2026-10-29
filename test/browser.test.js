'use strict';
// The real guest page, in a real headless Chromium, under its real CSP —
// driven over the DevTools protocol (no extra dependencies: `ws` is already a
// dev dependency). Proves what the Node tests can't: the inlined modules,
// WebCrypto, the download path and the in-browser EXIF strip all work in a
// browser, and the hash-pinned CSP doesn't block the page's own code.
//
// Skipped when no Chromium is found. Set CHROME=/path/to/chrome to choose one.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const c = require('../src/crypto');
const exif = require('../src/shared/exif');
const { Relay } = require('../src/server');
const { Inbox } = require('../src/fsafe');
const { createHostEngine, sendPath } = require('../src/transfer');

function findChrome() {
  const cands = [process.env.CHROME];
  const pw = path.join(os.homedir(), '.cache', 'ms-playwright');
  try { for (const d of fs.readdirSync(pw).filter((n) => n.startsWith('chromium-')).sort().reverse()) cands.push(path.join(pw, d, 'chrome-linux', 'chrome')); } catch {}
  cands.push('/usr/bin/google-chrome', '/usr/bin/chromium');
  return cands.find((p) => { try { return p && fs.statSync(p).isFile() && !fs.readFileSync(p, 'latin1').slice(0, 2).startsWith('#!'); } catch { return false; } });
}
const CHROME = findChrome();
const JPG = '/usr/share/backgrounds/Clouds_by_Tibor_Mokanszki.jpg';
const SHOTS = process.env.SHOTS_DIR || '';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 20000) => { const t = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t > ms) throw new Error('timeout'); await wait(50); } };

// ---- tiny CDP client ----
async function launch() {
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-chrome-'));
  const child = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-port=0', `--user-data-dir=${prof}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((res, rej) => {
    let buf = '';
    const t = setTimeout(() => rej(new Error('chrome did not start')), 20000);
    child.stderr.on('data', (d) => { buf += d; const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf); if (m) { clearTimeout(t); res(m[1]); } });
  });
  const ws = new WebSocket(wsUrl, { perMessageDeflate: false });
  await new Promise((r) => ws.once('open', r));
  let id = 0;
  const pending = new Map(), listeners = [];
  ws.on('message', (raw) => {
    const m = JSON.parse(raw);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); }
    else for (const l of listeners) l(m);
  });
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
  return {
    send, on: (fn) => listeners.push(fn), prof,
    close() { try { ws.close(); } catch {} try { child.kill('SIGKILL'); } catch {} fs.rmSync(prof, { recursive: true, force: true }); },
  };
}

test('real page in real Chromium: both directions, chat, EXIF strip, CSP clean, tamper goes red', { skip: !CHROME && 'no Chromium found', timeout: 120000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-browser-'));
  const dl = path.join(dir, 'downloads'); fs.mkdirSync(dl);
  const secret = c.newSessionKey(), salt = c.randomB64u(16), token = c.randomB64u(24);
  const keys = await c.deriveKeys(secret, salt);
  const relay = new Relay({ token, salt, keys, port: 0, maxFails: 5, graceSec: 30 });
  const inbox = new Inbox(path.join(dir, 'inbox'));
  const engine = await createHostEngine({ relay, secret: c.fromB64u(secret), encKey: keys.encKey, inbox });
  const port = await relay.listen();
  const hostEv = [];
  for (const e of ['offer', 'done', 'failed', 'chat']) engine.on(e, (...a) => hostEv.push([e, ...a]));
  relay.on('tamper', (why) => hostEv.push(['tamper', why]));
  relay.on('selfdestruct', () => {});
  const hostHas = (n, dir) => hostEv.find((x) => x[0] === n && (!dir || (x[1] && x[1].dir === dir)));

  const cdp = await launch();
  t.after(() => { cdp.close(); engine.destroy(); relay.destroy(); fs.rmSync(dir, { recursive: true, force: true }); });

  const problems = [];
  const downloads = new Map();
  cdp.on((m) => {
    if (m.method === 'Runtime.exceptionThrown') problems.push('exception: ' + JSON.stringify(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text));
    if (m.method === 'Log.entryAdded' && /Content Security Policy|Refused/i.test(m.params.entry.text)) problems.push('csp: ' + m.params.entry.text);
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') problems.push('console.error: ' + JSON.stringify(m.params.args.map((a) => a.value || a.description)));
    if (m.method === 'Browser.downloadWillBegin') downloads.set(m.params.guid, { name: m.params.suggestedFilename });
    if (m.method === 'Browser.downloadProgress' && m.params.state === 'completed') downloads.get(m.params.guid).done = true;
  });
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: dl, eventsEnabled: true });
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p) => cdp.send(m, p, sessionId);
  await S('Runtime.enable'); await S('Log.enable'); await S('Page.enable'); await S('DOM.enable');
  const js = async (expression) => {
    const r = await S('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error('page eval: ' + r.exceptionDetails.text);
    return r.result.value;
  };
  const click = (label) => js(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === ${JSON.stringify(label)} && !x.disabled); if (!b) return false; b.click(); return true; })()`);
  const shot = async (name, scheme) => {
    if (!SHOTS) return;
    await S('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
    await wait(150);
    const { data } = await S('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(SHOTS, name), Buffer.from(data, 'base64'));
  };
  await S('Emulation.setDeviceMetricsOverride', { width: 520, height: 900, deviceScaleFactor: 1, mobile: false });

  // 1. tap the link
  await S('Page.navigate', { url: `http://127.0.0.1:${port}/r/${token}#k=${secret}` });
  await until(() => js('!!(globalThis.__ftproxyPage && __ftproxyPage.authed)'));
  assert.equal(await js('location.hash'), '', 'key scrubbed from the address bar');

  // 2. chat both ways (inside the envelope)
  await engine.chat('hey — sending the photo now');
  await until(() => js(`[...document.querySelectorAll('.peer .bubble')].some((b) => b.textContent.includes('sending the photo'))`));
  await js(`(() => { const m = document.getElementById('msg'); m.value = 'got it, go ahead'; document.getElementById('composer').requestSubmit(); })()`);
  await until(() => hostHas('chat'));
  assert.equal(hostHas('chat')[1], 'got it, go ahead');

  // 3. host -> guest: a JPEG (Node strips it), accept in the page, real download
  await sendPath(engine, JPG, {});
  await until(() => js(`!!document.querySelector('.fcard') && [...document.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Accept')`));
  await shot('offer-dark.png', 'dark');
  assert.ok(await click('Accept'));
  await until(() => [...downloads.values()].some((d) => d.done), 30000);
  const d1 = [...downloads.entries()].find(([, d]) => d.done);
  assert.equal(d1[1].name, 'Clouds_by_Tibor_Mokanszki.jpg', 'download uses the cleaned name');
  const got = fs.readFileSync(path.join(dl, d1[0]));
  assert.ok(got.equals(Buffer.from(exif.strip(new Uint8Array(fs.readFileSync(JPG))).bytes)), 'downloaded bytes == stripped original');
  await until(() => js(`[...document.querySelectorAll('.fok')].some((e) => e.textContent.includes('verified'))`));
  await shot('received-dark.png', 'dark');
  await shot('received-light.png', 'light');

  // 4. guest -> host: pick the same JPEG through the real <input type=file>;
  //    the BROWSER strips the metadata, hashes it with the JS SHA-256, offers it.
  const { root } = await S('DOM.getDocument');
  const { nodeId } = await S('DOM.querySelector', { nodeId: root.nodeId, selector: '#picker' });
  await S('DOM.setFileInputFiles', { nodeId, files: [JPG] });
  await until(() => click('Offer file'));
  await until(() => hostHas('offer'), 30000);
  assert.equal(hostHas('offer')[1].stripped, true, 'browser stripped the metadata');
  await engine.accept();
  await until(() => hostHas('done', 'in') || hostHas('failed'), 30000);
  assert.ok(hostHas('done', 'in'), 'host verified the browser-sent file: ' + JSON.stringify(hostHas('failed') || ''));
  const saved = fs.readFileSync(hostHas('done', 'in')[2]);
  assert.ok(!saved.includes('Exif\0'), 'no Exif reached the host');
  assert.ok(saved.equals(got), 'browser strip == Node strip, byte for byte (same shared code)');
  await until(() => js(`[...document.querySelectorAll('.fok')].some((e) => e.textContent.includes('Delivered'))`));
  await shot('sent-light.png', 'light');

  assert.deepEqual(problems, [], 'no CSP violations, exceptions or console errors');

  // 5. a forged envelope from the "edge" -> page goes red and reports it
  relay.sendText(JSON.stringify({ t: 'x', s: 99, d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }));
  await until(() => js(`document.getElementById('alarm').classList.contains('show')`));
  await until(() => hostHas('tamper'));
  assert.match(hostHas('tamper')[1], /guest detected/);
  await shot('tamper-dark.png', 'dark');
});

// The phone leaving the page must end the session for the host too: closing
// the tab and navigating away both fire pagehide -> bye -> burn now.
for (const how of ['close the tab', 'navigate away']) {
  test(`real page in real Chromium: ${how} -> host burns at once; heartbeat answered meanwhile`, { skip: !CHROME && 'no Chromium found', timeout: 60000 }, async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-browser-'));
    const secret = c.newSessionKey(), salt = c.randomB64u(16), token = c.randomB64u(24);
    const keys = await c.deriveKeys(secret, salt);
    const relay = new Relay({ token, salt, keys, port: 0, maxFails: 5, graceSec: 30, heartbeatSec: 0.2 });
    const engine = await createHostEngine({ relay, secret: c.fromB64u(secret), encKey: keys.encKey, inbox: new Inbox(path.join(dir, 'inbox')) });
    const port = await relay.listen();
    let burned = null;
    relay.on('selfdestruct', (why) => { burned = burned || why; });
    const cdp = await launch();
    t.after(() => { cdp.close(); engine.destroy(); relay.destroy(); fs.rmSync(dir, { recursive: true, force: true }); });

    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    const S = (m, p) => cdp.send(m, p, sessionId);
    const js = async (expression) => (await S('Runtime.evaluate', { expression, returnByValue: true })).result.value;
    await S('Runtime.enable'); await S('Page.enable');
    await S('Page.navigate', { url: `http://127.0.0.1:${port}/r/${token}#k=${secret}` });
    await until(() => js('!!(globalThis.__ftproxyPage && __ftproxyPage.authed)'));

    await wait(1500);                        // ~7 heartbeat intervals: the page must be answering
    assert.ok(relay.hasClient(), 'still connected: the real page answers pings');
    assert.equal(burned, null);

    const t0 = Date.now();
    if (how === 'close the tab') await cdp.send('Target.closeTarget', { targetId });
    else await S('Page.navigate', { url: 'about:blank' });
    await until(() => burned, 5000);
    assert.equal(burned, 'the guest closed the page', 'bye, not the grace timer');
    assert.ok(Date.now() - t0 < 5000);
  });
}
