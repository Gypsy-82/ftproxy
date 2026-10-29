'use strict';
// Terminal rendering. ASCII-only so it renders correctly on ANY terminal
// regardless of locale/encoding (no box-drawing or Unicode glyphs to mojibake).
// Colour is ANSI-only, which is universally supported. The one exception is
// the opt-in QR code (qrBlock), which falls back to '##' blocks off UTF-8.

const colors = require('./colors');
const qr = require('./qr');

const useColor = !!process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

// Message colours (user-configurable): You (local) vs Target (remote).
let YOU = colors.code(colors.load().you);
let TARGET = colors.code(colors.load().target);
function setColors(cfg) { YOU = colors.code(cfg.you); TARGET = colors.code(cfg.target); }
function you(s) { return paint(YOU, s); }
function target(s) { return paint(TARGET, s); }
function swatch(name, s) { return paint(colors.code(name), s == null ? name : s); }

const C = {
  green: (s) => paint('32', s),
  greenB: (s) => paint('1;32', s),
  magenta: (s) => paint('35', s),
  magentaB: (s) => paint('1;35', s),
  cyan: (s) => paint('36', s),
  gray: (s) => paint('90', s),
  dim: (s) => paint('2', s),
  red: (s) => paint('31', s),
};

const cols = () => process.stdout.columns || 80;
const WIDTH = () => Math.min(cols(), 80);
const now = () => new Date().toTimeString().slice(0, 5);

function wrap(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  if (!words.length) return [''];
  const lines = [];
  let line = '';
  for (let word of words) {
    while (word.length > width) {
      if (line) { lines.push(line); line = ''; }
      lines.push(word.slice(0, width));
      word = word.slice(width);
    }
    if (!line) line = word;
    else if ((line + ' ' + word).length <= width) line += ' ' + word;
    else { lines.push(line); line = word; }
  }
  if (line) lines.push(line);
  return lines;
}

// One chat line:  "HH:MM  message". No name label — the colour is the sender:
// you (local) = your colour, the other person = their colour.
function bubble({ text, side }) {
  const time = now();
  const color = side === 'right' ? you : target;
  const headLen = 5 + 2; // HH:MM + two spaces
  const avail = Math.max(20, WIDTH() - headLen);
  const rows = String(text).split('\n').flatMap((l) => wrap(l, avail));
  const indent = ' '.repeat(headLen);
  const head = C.dim(time) + '  ';
  return rows.map((row, i) => (i === 0 ? head : indent) + color(row)).join('\n');
}

// Centred status line:  "-------- text --------"
function system(text) {
  const width = WIDTH();
  const t = ` ${text} `;
  const total = Math.max(0, width - t.length);
  const l = Math.floor(total / 2);
  return C.gray('-'.repeat(l)) + C.dim(t) + C.gray('-'.repeat(total - l));
}

// Key-verification indicator.
function keyLine(verified, safety) {
  if (verified) return '  ' + C.green('* key verified') + C.dim(safety ? '   safety ' + safety : '');
  return '  ' + C.red('! KEYS CHANGED');
}

// Full-width red alarm banner (white-on-red).
function alarm(text) {
  const w = WIDTH();
  const bg = (s) => paint('1;97;41', s);
  const bar = (s) => { const t = ' ' + s; return bg(t + ' '.repeat(Math.max(0, w - t.length))); };
  return [bar(''), bar('! ' + text), bar('')].join('\n');
}

// One link to hand off. The key rides in its #fragment, so the link IS the
// secret: it opens straight into the chat, and anyone who sees it can walk in.
function shareBlock({ link, safety }) {
  const rule = C.dim('-'.repeat(WIDTH()));
  const L = [];
  L.push(rule);
  L.push('  ' + C.greenB('SEND THIS LINK') + C.dim('  - one tap and they can swap files with you'));
  L.push('');
  L.push('  ' + C.green('1. Link') + C.dim('  (all of it, including the #key on the end)'));
  L.push('       ' + C.cyan(link));
  L.push('');
  L.push('  ' + C.green('2. Safety code') + C.dim('  (you should both see the same)   ') + C.greenB(safety));
  L.push('');
  L.push('  ' + C.dim('The link is the key - send it privately, to one person, once.'));
  L.push(rule);
  return L.join('\n');
}

function utf8Locale(env = process.env) {
  const loc = env.LC_ALL || env.LC_CTYPE || env.LANG;
  return !loc || /utf-?8/i.test(loc);
}

// A QR code as terminal lines. Dark-on-light with explicit colours, because
// an inverted code (light on a dark theme) doesn't scan on every phone. UTF-8:
// two modules per cell with an upper half block. Otherwise: two cells per module.
// Without colour, dark modules are ink ('##' / block glyphs).
function qrLines(code, { color = useColor, unicode = utf8Locale() } = {}) {
  const Q = 4, n = code.size + 2 * Q;            // 4-module quiet zone
  const dark = (x, y) => {
    x -= Q; y -= Q;
    return x >= 0 && y >= 0 && x < code.size && y < code.size && code.modules[y][x] === 1;
  };
  const lines = [];
  if (unicode) {
    for (let y = 0; y < n; y += 2) {
      let s = '';
      for (let x = 0; x < n; x++) {
        const t = dark(x, y), b = dark(x, y + 1);
        s += color ? `\x1b[${t ? 30 : 97};${b ? 40 : 107}m▀` : (t ? (b ? '█' : '▀') : (b ? '▄' : ' '));
      }
      lines.push(color ? s + '\x1b[0m' : s);
    }
  } else {
    for (let y = 0; y < n; y++) {
      let s = '';
      for (let x = 0; x < n; x++) s += color ? `\x1b[${dark(x, y) ? 40 : 107}m  ` : (dark(x, y) ? '##' : '  ');
      lines.push(color ? s + '\x1b[0m' : s);
    }
  }
  return { lines, width: unicode ? n : 2 * n };
}

// The link as a QR code for a phone camera. Same secret as the link: printed
// only to this terminal, never written anywhere.
function qrBlock(link) {
  let code;
  try { code = qr.encode(link, 'M'); } catch (e) { return '  ' + C.red('! no QR code: ' + e.message) + C.dim(' - send the link instead'); }
  const { lines, width } = qrLines(code);
  // A wrapped line would scramble the code, so refuse rather than print it.
  if (width + 2 > cols()) return '  ' + C.red(`! the QR code needs ${width + 2} columns, this terminal has ${cols()}`) + C.dim(' - widen it, then /qr');
  return [
    '  ' + C.greenB('SCAN TO JOIN') + C.dim('  - the same link (and key) as a QR code'),
    '',
    ...lines.map((l) => '  ' + l),
    '',
    '  ' + C.dim('Anyone who can see this screen can scan it. Use the phone\'s own camera app,'),
    '  ' + C.dim('not a third-party scanner - those can log or upload what they read.'),
  ].join('\n');
}

// Clean title bar for the chat, e.g.
//   ==================================================================
//     ftproxy   private file line                            key 19A8-0172
//   ==================================================================
//     self-destructs in 60 min   -   /help for commands
function banner({ ttlMin, safety }) {
  const w = WIDTH();
  const bar = C.green('='.repeat(w));
  const left = '  ftproxy';
  const mid = '   private file line';
  const right = safety ? 'key ' + safety : '';
  const pad = Math.max(2, w - left.length - mid.length - right.length - 2);
  const title = C.greenB(left) + C.dim(mid) + ' '.repeat(pad) + C.dim(right) + '  ';
  const status = C.dim(`  self-destructs in ${ttlMin} min   -   /help for commands`);
  return [bar, title, bar, status].join('\n');
}

module.exports = { C, bubble, system, banner, shareBlock, qrBlock, qrLines, utf8Locale, keyLine, alarm, useColor, WIDTH, setColors, swatch, you, target };
