'use strict';
// Filename sanitizer (DESIGN.md §7) and the quarantine inbox (§8).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { cleanName } = require('../src/shared/names');
const { Inbox, PART_RE } = require('../src/fsafe');
const { openHostSource } = require('../src/hostfile');

const SAFE = /^[\p{L}\p{N} ._()-]+\.(txt|png|jpg|mp4|pdf)$/u;

test('hostile names all come out safe', () => {
  const cases = {
    '../../etc/passwd': 'passwd.txt',
    '..\\..\\Windows\\System32\\evil.png': 'evil.png',
    'a‮fdp.exe': 'afdp.pdf',             // RLO stripped; sender's ".exe" dropped; OUR ext
    '\x1b]52;c;Y3VybCBldmlsfGJhc2g=\x07pwn.txt': null,
    'CON': '_CON.txt', 'nul.txt': '_nul.txt', 'COM1.pdf': '_COM1.pdf',
    '-rf.txt': '_rf.txt',
    'report final!!.pdf': 'report final_.pdf',
    '\u{1F510} vacation.jpeg': '_ vacation.jpg',
    '...': '', '': '', '.bashrc': 'bashrc.txt',
    'zero​width﻿.txt': 'zerowidth.txt',
  };
  const types = { 'evil.png': 'png', 'afdp.pdf': 'pdf', '_COM1.pdf': 'pdf', 'report final_.pdf': 'pdf', '_ vacation.jpg': 'jpeg' };
  for (const [raw, want] of Object.entries(cases)) {
    const type = (want && types[want]) || (raw.includes('fdp') ? 'pdf' : 'txt');
    const got = cleanName(raw, type);
    if (want !== null) assert.equal(got, want, JSON.stringify(raw));
    if (got) {
      assert.match(got, SAFE, JSON.stringify(raw));
      assert.ok(!got.includes('/') && !got.includes('\\') && !got.startsWith('.') && !got.startsWith('-'));
    }
  }
  const osc = cleanName('\x1b]52;c;Y3VybCBldmlsfGJhc2g=\x07pwn.txt', 'txt');
  assert.ok(!/[\x00-\x1f\x7f]/.test(osc), 'no escape bytes survive: ' + osc);
});

test('names are capped at 100 bytes UTF-8 without splitting a character', () => {
  const long = cleanName('é'.repeat(300) + '.txt', 'txt');
  assert.ok(Buffer.byteLength(long.slice(0, -4)) <= 100);
  assert.ok(!long.includes('�'));
  assert.equal(long.slice(0, -4), 'é'.repeat(50));
});

test('extension always comes from the detected type', () => {
  assert.equal(cleanName('invoice.pdf.exe', 'png'), 'invoice.pdf.png');
  assert.equal(cleanName('photo.JPG', 'jpeg'), 'photo.jpg');
});

function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'tx-inbox-')); }

test('inbox is created 0700 and refuses symlinks / loose perms', () => {
  const root = tmpdir();
  try {
    const box = new Inbox(path.join(root, 'in'));
    assert.equal(fs.statSync(box.dir).mode & 0o777, 0o700);

    fs.mkdirSync(path.join(root, 'real'), { mode: 0o700 });
    fs.symlinkSync(path.join(root, 'real'), path.join(root, 'link'));
    assert.throws(() => new Inbox(path.join(root, 'link')), /symlink/);

    fs.mkdirSync(path.join(root, 'loose')); fs.chmodSync(path.join(root, 'loose'), 0o777);
    assert.throws(() => new Inbox(path.join(root, 'loose')), /world-writable/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('sink: writes a 0600 partial, commits to a timestamped name, never clobbers', async () => {
  const root = tmpdir();
  try {
    const box = new Inbox(path.join(root, 'in'));
    const view = { name: 'notes.txt', type: 'txt', size: 5 };
    const s1 = box.open(view);
    assert.match(path.basename(s1.partPath), PART_RE);
    assert.equal(fs.statSync(s1.partPath).mode & 0o777, 0o600);
    await s1.write(0, new TextEncoder().encode('hello'));
    const p1 = await s1.commit();
    assert.match(path.basename(p1), /^\d{8}-\d{6}-notes\.txt$/);
    assert.equal(fs.readFileSync(p1, 'utf8'), 'hello');

    const s2 = box.open(view); await s2.write(0, new TextEncoder().encode('again'));
    const p2 = await s2.commit();
    assert.notEqual(p1, p2, 'same second, same name -> suffixed, not overwritten');
    assert.equal(fs.readFileSync(p1, 'utf8'), 'hello');
    assert.match(path.basename(p2), /-notes-1\.txt$/);
    assert.equal(fs.readdirSync(box.dir).filter((n) => PART_RE.test(n)).length, 0, 'no partials left');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('sink: abort deletes the partial; startup sweep clears stale ones', async () => {
  const root = tmpdir();
  try {
    const box = new Inbox(path.join(root, 'in'));
    const s = box.open({ name: 'x.txt', type: 'txt', size: 3 });
    await s.write(0, new Uint8Array([1, 2, 3]));
    s.abort();
    assert.equal(fs.existsSync(s.partPath), false);

    const stale = box.open({ name: 'y.txt', type: 'txt', size: 1 });   // simulate a crash: never committed
    fs.writeFileSync(path.join(box.dir, 'keep-me.txt'), 'user file');
    assert.equal(box.sweep(), 1);
    assert.equal(fs.existsSync(stale.partPath), false);
    assert.ok(fs.existsSync(path.join(box.dir, 'keep-me.txt')), 'sweep only touches our .part files');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('disk-space check refuses when the file would not fit', () => {
  const root = tmpdir();
  try {
    const box = new Inbox(path.join(root, 'in'));
    assert.equal(box.checkSpace(1), null);
    assert.match(box.checkSpace(Number.MAX_SAFE_INTEGER), /disk space/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('/send source: refuses symlinks, dirs, devices and disallowed types; detects type by bytes', async () => {
  const root = tmpdir();
  try {
    const secret = path.join(root, 'id_ed25519'); fs.writeFileSync(secret, 'PRIVATE KEY');
    fs.symlinkSync(secret, path.join(root, 'innocent.txt'));
    await assert.rejects(openHostSource(path.join(root, 'innocent.txt')), /symlink/);
    await assert.rejects(openHostSource(root), /regular file/);
    await assert.rejects(openHostSource('/dev/zero'), /regular file/);
    fs.writeFileSync(path.join(root, 'bin.txt'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 1, 2]));   // ELF named .txt
    await assert.rejects(openHostSource(path.join(root, 'bin.txt')), /not an allowed type/);

    fs.writeFileSync(path.join(root, 'pic.pdf'), Buffer.from('89504e470d0a1a0a0000', 'hex'));     // PNG named .pdf
    const src = await openHostSource(path.join(root, 'pic.pdf'));
    assert.equal(src.type, 'png'); assert.equal(src.name, 'pic.png');
    src.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('/send source: a file modified mid-send is cancelled', async () => {
  const root = tmpdir();
  try {
    const p = path.join(root, 'grow.txt'); fs.writeFileSync(p, 'a'.repeat(200000));
    const src = await openHostSource(p);
    await src.read(0);
    fs.appendFileSync(p, 'more');
    await assert.rejects(src.read(1), /changed/);
    src.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
