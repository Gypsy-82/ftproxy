'use strict';
// Bare "/send" file picker (src/picker.js) and how the TUI uses it.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { findPicker, pickFile } = require('../src/picker');
const { Tui, sendHint } = require('../src/tui');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ftproxy-picker-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// A fake dialog: prints `out` (from a file, so no quoting games) and exits `code`.
function fake(name, out, code = 0) {
  const data = path.join(tmp, name + '.out');
  fs.writeFileSync(data, out);
  const bin = path.join(tmp, name);
  fs.writeFileSync(bin, `#!/bin/sh\ncat '${data}'\nexit ${code}\n`, { mode: 0o700 });
  return { cmd: bin, args: [] };
}

test('findPicker: needs a display; prefers zenity, then kdialog', () => {
  const all = () => true;
  assert.equal(findPicker({}, all), null, 'no DISPLAY/WAYLAND_DISPLAY (e.g. ssh) -> none');
  assert.equal(findPicker({ DISPLAY: ':0' }, all).cmd, 'zenity');
  assert.equal(findPicker({ WAYLAND_DISPLAY: 'wayland-0' }, (c) => c === 'kdialog').cmd, 'kdialog');
  assert.equal(findPicker({ DISPLAY: ':0' }, () => false), null);
  for (const pk of [findPicker({ DISPLAY: ':0' }, all), findPicker({ DISPLAY: ':0' }, (c) => c === 'kdialog')]) {
    assert.ok(pk.args.every((a) => typeof a === 'string'), 'fixed string args');
    assert.ok(pk.args.join(' ').includes('*.pdf'), 'filters to the allowed types');
  }
});

test('pickFile: returns the chosen absolute path, keeps odd names intact', async () => {
  assert.equal(await pickFile(fake('ok', '/home/u/My Photo.jpg\n')).promise, '/home/u/My Photo.jpg');
  assert.equal(await pickFile(fake('nl', '/home/u/a\nb.txt\n')).promise, '/home/u/a\nb.txt', 'only the terminator is stripped');
});

test('pickFile: cancel, junk, relative, NUL, oversized and missing binary all give null', async () => {
  assert.equal(await pickFile(fake('cancel', '', 1)).promise, null, 'cancelled dialog');
  assert.equal(await pickFile(fake('fail', '/etc/passwd\n', 5)).promise, null, 'non-zero exit ignores output');
  assert.equal(await pickFile(fake('rel', 'relative/x.txt\n')).promise, null);
  assert.equal(await pickFile(fake('empty', '\n')).promise, null);
  assert.equal(await pickFile(fake('nul', '/a\0/b.txt\n')).promise, null);
  assert.equal(await pickFile(fake('big', '/' + 'a'.repeat(20000) + '\n')).promise, null);
  assert.equal(await pickFile({ cmd: path.join(tmp, 'does-not-exist'), args: [] }).promise, null);
});

test('pickFile: kill() closes an open dialog', async () => {
  const bin = path.join(tmp, 'hang');
  fs.writeFileSync(bin, '#!/bin/sh\nexec sleep 30\n', { mode: 0o700 });
  const t0 = Date.now();
  const pk = pickFile({ cmd: bin, args: [] });
  setTimeout(pk.kill, 50);
  assert.equal(await pk.promise, null);
  assert.ok(Date.now() - t0 < 5000);
});

// Drive Tui#_send without a real terminal.
function fakeTui({ client = true, picker = null, chosen = null } = {}) {
  const t = Object.create(Tui.prototype);
  const log = [];
  Object.assign(t, {
    keepMeta: false, picking: null, log, picks: 0,
    relay: { hasClient: () => (typeof client === 'function' ? client() : client) },
    _sys: (m) => log.push(m),
    findPicker: () => picker,
    pickFile: () => { t.picks++; return { promise: Promise.resolve(chosen), kill() {} }; },
  });
  return t;
}

test('/send with no path: no guest -> no dialog; no picker -> usage', async () => {
  const a = fakeTui({ client: false, picker: { cmd: 'x', args: [] } });
  await a._send('');
  assert.equal(a.picks, 0, 'never opens a dialog with nobody to send to');
  assert.match(a.log.join('\n'), /no guest connected/);

  const b = fakeTui({ picker: null });
  await b._send('');
  assert.equal(b.picks, 0);
  assert.match(b.log.join('\n'), /usage: \/send .*drag a file/);
});

test('/send with no path: cancelled dialog sends nothing; guest leaving mid-pick sends nothing', async () => {
  const a = fakeTui({ picker: { cmd: 'x', args: [] }, chosen: null });
  await a._send('');
  assert.equal(a.picks, 1);
  assert.match(a.log.join('\n'), /no file chosen/);
  assert.equal(a.picking, null, 'picker slot released');

  let n = 0;
  const b = fakeTui({ client: () => n++ === 0, picker: { cmd: 'x', args: [] }, chosen: '/tmp/x.txt' });
  await b._send('');
  assert.match(b.log.join('\n'), /guest disconnected - not sent/);
});

test('/send with no path: only one dialog at a time', async () => {
  const t = fakeTui({ picker: { cmd: 'x', args: [] } });
  t.picking = { kill() {} };
  await t._send('');
  assert.equal(t.picks, 0);
  assert.match(t.log.join('\n'), /already open/);
});

test('/send: a picked path goes through the same checks as a typed one', async () => {
  const link = path.join(tmp, 'link.txt');
  fs.writeFileSync(path.join(tmp, 'real.txt'), 'hi');
  fs.symlinkSync(path.join(tmp, 'real.txt'), link);
  const t = fakeTui({ picker: { cmd: 'x', args: [] }, chosen: link });
  t.engine = { offer: async () => { throw new Error('must not be offered'); } };
  await assert.rejects(t._send(''), /symlink/i);
});

test('connect hint mentions /send and drag-and-drop', () => {
  const h = sendHint().replace(/\x1b\[[0-9;]*m/g, '');
  assert.match(h, /\/send/);
  assert.match(h, /drag/);
});
