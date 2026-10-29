'use strict';
// Magic-byte validation (DESIGN.md §6) and lossless JPEG metadata strip (§11).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const ft = require('../src/shared/filetype');
const exif = require('../src/shared/exif');

const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
const JPEG = Buffer.from('ffd8ffe000104a464946', 'hex');
const PDF = Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1');
const MP4 = Buffer.concat([Buffer.from([0, 0, 0, 0x20]), Buffer.from('ftypisom\0\0\x02\0isomiso2mp41', 'latin1')]);

function validate(type, chunks) {
  const v = ft.validator(type);
  for (const c of chunks) v.push(new Uint8Array(c));
  v.finish();
}

test('each allowed type passes its own validator', () => {
  for (const [t, b] of [['png', PNG], ['jpeg', JPEG], ['pdf', PDF], ['mp4', MP4], ['txt', Buffer.from('hello\nworld é\u{1F510}')]]) {
    assert.doesNotThrow(() => validate(t, [b]), t);
    assert.equal(ft.sniff(new Uint8Array(b)), t, 'sniff ' + t);
  }
});

test('declared type must match the bytes', () => {
  assert.throws(() => validate('pdf', [PNG]), /not a valid PDF/, 'PNG renamed .pdf');
  assert.throws(() => validate('png', [JPEG]));
  assert.throws(() => validate('mp4', [Buffer.concat([Buffer.from([0, 0, 0, 0x20]), Buffer.from('ftypqt  ', 'latin1')])]), undefined, 'QuickTime brand not allowed');
  assert.throws(() => validate('jpeg', []), undefined, 'empty file is not a JPEG');
});

test('txt: a NUL deep in the file fails, even past the first chunk', () => {
  const a = Buffer.alloc(65536, 0x61);
  const b = Buffer.alloc(65536, 0x61); b[70000 - 65536] = 0;
  assert.throws(() => validate('txt', [a, b]), /NUL/);
});

test('txt: invalid UTF-8 and a character split at EOF both fail; a split across chunks passes', () => {
  assert.throws(() => validate('txt', [Buffer.from([0x61, 0xff, 0x61])]), /UTF-8/);
  const e = Buffer.from('é');                       // 2 bytes
  assert.doesNotThrow(() => validate('txt', [Buffer.from([0x61, e[0]]), Buffer.from([e[1], 0x62])]));
  assert.throws(() => validate('txt', [Buffer.from([0x61, e[0]])]), /mid-character/);
});

test('polyglot: %PDF- after the first 1024 bytes is not a PDF', () => {
  const late = Buffer.concat([Buffer.alloc(1024, 0x20), PDF]);
  assert.throws(() => validate('pdf', [late]));
  const edge = Buffer.concat([Buffer.alloc(1019, 0x20), PDF]);   // marker ends exactly at byte 1024
  assert.doesNotThrow(() => validate('pdf', [edge]));
  assert.throws(() => validate('pdf', [Buffer.concat([Buffer.alloc(1020, 0x20), PDF])]), undefined, 'straddles 1024');
});

test('svg/html/zip are never an allowed type', () => {
  assert.throws(() => ft.validator('svg'));
  assert.throws(() => ft.validator('html'));
  assert.equal(ft.sniff(new Uint8Array(Buffer.from('PK\x03\x04', 'latin1'))), 'txt', 'zip sniffs as txt candidate...');
  assert.throws(() => validate('txt', [Buffer.from('PK\x03\x04\x00\x00', 'latin1')]), undefined, '...and then fails txt validation');
});

// ---------- EXIF ----------
const seg = (m, payload) => { const p = Buffer.from(payload, 'latin1'); const h = Buffer.alloc(4); h[0] = 0xff; h[1] = m; h.writeUInt16BE(p.length + 2, 2); return Buffer.concat([h, p]); };
function markers(b) {
  const out = [];
  let i = 2;
  while (i < b.length) {
    if (b[i] !== 0xff) { i++; continue; }
    const m = b[i + 1];
    if (m === 0x00 || (m >= 0xd0 && m <= 0xd7) || m === 0xff) { i += m === 0xff ? 1 : 2; continue; }
    if (m === 0xd9) { out.push('EOI'); break; }
    const len = b.readUInt16BE(i + 2);
    out.push(m.toString(16) + ':' + b.subarray(i + 4, i + 2 + Math.min(len, 6)).toString('latin1'));
    i += 2 + len;
  }
  return out;
}

test('exif: synthetic JPEG with GPS, comment, IPTC and a trailing MPF image is fully cleaned', () => {
  const scan = Buffer.from([0x12, 0xff, 0x00, 0x34, 0xff, 0xd3, 0x56]);   // stuffing + RST3 inside the scan
  const trailer = Buffer.concat([Buffer.from([0xff, 0xd8]), seg(0xe1, 'Exif\0\0GPS:51.5,-0.12'), Buffer.from([0xff, 0xd9])]);
  const jpg = Buffer.concat([
    Buffer.from([0xff, 0xd8]), seg(0xe0, 'JFIF\0\x01\x01'), seg(0xe1, 'Exif\0\0GPS:51.5,-0.12'),
    seg(0xe2, 'MPF\0index'), seg(0xe2, 'ICC_PROFILE\0data'), seg(0xed, 'Photoshop 3.0\0IPTC'),
    seg(0xfe, 'shot at home'), seg(0xee, 'Adobe'), seg(0xdb, 'qt'), seg(0xc0, 'sof'), seg(0xda, 'sos'), scan,
    Buffer.from([0xff, 0xd9]), trailer,
  ]);
  const { bytes, removed } = exif.strip(new Uint8Array(jpg));
  const out = Buffer.from(bytes);
  assert.deepEqual(markers(out), ['e0:JFIF', 'e2:ICC_', 'ee:Adob', 'db:qt', 'c0:sof', 'da:sos', 'EOI']);
  assert.ok(!out.includes('GPS'), 'no GPS anywhere — including the trailing MPF image');
  assert.ok(!out.includes('shot at home') && !out.includes('IPTC'));
  assert.ok(out.includes(scan), 'entropy-coded data untouched');
  assert.equal(removed, jpg.length - out.length);
});

test('exif: malformed structure refuses instead of guessing', () => {
  assert.throws(() => exif.strip(new Uint8Array([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x40, 1, 2])), /overruns/);
  assert.throws(() => exif.strip(new Uint8Array([0x89, 0x50, 0x4e, 0x47])), /no SOI/);
  assert.throws(() => exif.strip(new Uint8Array(Buffer.concat([Buffer.from([0xff, 0xd8]), seg(0xda, 's'), Buffer.from([1, 2, 3])]))), /off the end/);
});

const REAL = '/usr/share/backgrounds/Clouds_by_Tibor_Mokanszki.jpg';
const hasFfmpeg = spawnSync('ffmpeg', ['-version'], { stdio: 'ignore' }).status === 0;
test('exif: real progressive JPEG decodes to IDENTICAL pixels after stripping', { skip: !(fs.existsSync(REAL) && hasFfmpeg) && 'needs ffmpeg + sample jpeg' }, () => {
  const orig = fs.readFileSync(REAL);
  const { bytes, removed } = exif.strip(new Uint8Array(orig));
  const out = Buffer.from(bytes);
  assert.ok(removed > 50000, `removed ${removed} bytes of Exif/XMP`);
  assert.ok(!out.includes('Exif\0') && !out.includes('http://ns.adobe.com/xap'), 'no Exif or XMP left');
  assert.ok(out.includes('ICC_PROFILE'), 'colour profile kept');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tx-exif-'));
  try {
    const p = path.join(tmp, 's.jpg'); fs.writeFileSync(p, out);
    const px = (f) => spawnSync('ffmpeg', ['-v', 'error', '-i', f, '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-'], { maxBuffer: 1 << 30 }).stdout;
    const a = px(REAL), b = px(p);
    assert.ok(a.length > 1e6, 'decoded something');
    assert.ok(a.equals(b), 'pixel-identical');
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
