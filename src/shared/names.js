// Filename sanitizer (DESIGN.md §7). A filename from the peer is attacker-
// controlled input that lands in two dangerous sinks: a filesystem (path
// traversal, reserved device names, option-injection like "-rf") and a
// terminal (ANSI/OSC escapes, bidi overrides that make "gpj.exe" read as
// "exe.jpg"). cleanName() is deliberately boring: basename only, a small
// allowlist of characters, a hard byte cap, and an extension we choose.
//
// ISOMORPHIC: runs in Node and is inlined verbatim into the guest page.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('names', function (require) {
  'use strict';

  const { EXT } = require('./filetype');
  const MAX_BASE_BYTES = 100;
  const te = new TextEncoder();

  // C0/C1 controls + DEL, then every Unicode "format" char (\p{Cf}): zero-width
  // joiners, bidi embeddings/overrides/isolates, BOM, and friends.
  const CONTROLS = /[\u0000-\u001F\u007F-\u009F]/gu;
  const FORMAT = /[\p{Cf}​-‏‪-‮⁦-⁩﻿]/gu;
  const DISALLOWED = /[^\p{L}\p{N} ._()-]/gu;
  const RESERVED = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])$/i;

  function capBytes(s, max) {
    let out = '';
    let n = 0;
    for (const ch of s) {                       // by code point: never split a character
      const len = te.encode(ch).length;
      if (n + len > max) break;
      out += ch; n += len;
    }
    return out;
  }
  function trimEdges(s) { return s.replace(/^[\s.]+|[\s.]+$/gu, ''); }

  // Returns "<safe base><canonical ext>", or '' when nothing usable is left
  // (the receiver rejects such an offer rather than inventing a name).
  function cleanName(raw, type) {
    const ext = EXT[type];
    if (!ext) throw new Error('type not allowed');
    let s = String(raw == null ? '' : raw);
    s = s.split(/[\/\\]/).pop();                // 1. basename only
    s = s.normalize('NFC')                      // 2. normalize, strip controls/format chars
      .replace(CONTROLS, '')
      .replace(FORMAT, '');
    const dot = s.lastIndexOf('.');             // 1b. drop the sender's extension
    if (dot > 0) s = s.slice(0, dot);
    s = s.replace(DISALLOWED, '_')              // 3. allowlist, collapse, trim
      .replace(/_+/g, '_')
      .replace(/\.{2,}/g, '.')
      .replace(/ {2,}/g, ' ');
    s = trimEdges(s);
    if (/^-/.test(s)) s = '_' + s.slice(1);     // "-rf" must never look like a flag
    if (RESERVED.test(s.split('.')[0])) s = '_' + s;   // 4. CON, NUL, COM1, ...
    s = trimEdges(capBytes(s, MAX_BASE_BYTES)); // 5. hard cap, then the ext WE chose
    return s ? s + ext : '';
  }

  return { cleanName, MAX_BASE_BYTES };
});
