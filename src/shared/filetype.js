// File-type detection by magic bytes (DESIGN.md §6). The sender's extension
// and declared type are CLAIMS; the receiver runs a validator over the actual
// decrypted bytes and aborts on mismatch. The saved extension always comes from
// the verified type, never from the sender's filename.
//
// No SVG, no HTML, no archives — ever. SVG/HTML carry script. (HTML that is
// valid UTF-8 can still arrive, but only as inert .txt.)
//
// ISOMORPHIC: runs in Node and is inlined verbatim into the guest page.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('filetype', function () {
  'use strict';

  const TYPES = ['txt', 'png', 'jpeg', 'mp4', 'pdf'];
  const EXT = { txt: '.txt', png: '.png', jpeg: '.jpg', mp4: '.mp4', pdf: '.pdf' };
  const LABEL = { txt: 'Text', png: 'PNG image', jpeg: 'JPEG image', mp4: 'MP4 video', pdf: 'PDF document' };
  const MP4_BRANDS = ['isom', 'iso2', 'mp41', 'mp42', 'avc1', 'M4V ', 'dash'];
  const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const PDF_SIG = [0x25, 0x50, 0x44, 0x46, 0x2d];          // %PDF-
  const PDF_WINDOW = 1024;

  function startsWith(b, sig, at = 0) {
    if (b.length < at + sig.length) return false;
    for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
    return true;
  }
  function ascii(b, from, to) { let s = ''; for (let i = from; i < to; i++) s += String.fromCharCode(b[i]); return s; }

  // Per-type check of the FIRST bytes of the file (the first chunk is ≥1024 B
  // unless the whole file is smaller, so these never span a chunk boundary).
  const HEAD = {
    png: (b) => startsWith(b, PNG_SIG),
    jpeg: (b) => startsWith(b, [0xff, 0xd8, 0xff]),
    mp4: (b) => b.length >= 12 && ascii(b, 4, 8) === 'ftyp' && MP4_BRANDS.includes(ascii(b, 8, 12)),
    pdf: (b) => {
      const end = Math.min(b.length, PDF_WINDOW) - PDF_SIG.length;   // marker must sit wholly inside 1024 B
      for (let i = 0; i <= end; i++) if (startsWith(b, PDF_SIG, i)) return true;
      return false;
    },
  };

  // Best guess for the SENDER from the first bytes. 'txt' is only a candidate:
  // the sender then runs validator('txt') over the whole file before offering.
  function sniff(head) {
    for (const t of ['png', 'jpeg', 'mp4', 'pdf']) if (HEAD[t](head)) return t;
    return 'txt';
  }

  // Streaming validator. push() each chunk in order, then finish(). Throws on
  // the first violation. txt is checked across EVERY chunk — a binary payload
  // can hide after a page of perfectly valid text.
  function validator(type) {
    if (!TYPES.includes(type)) throw new Error('type not allowed');
    let first = true;
    const dec = type === 'txt' ? new TextDecoder('utf-8', { fatal: true }) : null;
    return {
      push(chunk) {
        if (first) {
          first = false;
          if (type !== 'txt' && !HEAD[type](chunk)) throw new Error(`content is not a valid ${LABEL[type]}`);
        }
        if (dec) {
          if (chunk.indexOf(0) !== -1) throw new Error('text contains NUL bytes');
          try { dec.decode(chunk, { stream: true }); } catch { throw new Error('text is not valid UTF-8'); }
        }
      },
      finish() {
        if (first && type !== 'txt') throw new Error(`content is not a valid ${LABEL[type]}`);
        if (dec) { try { dec.decode(); } catch { throw new Error('text ends mid-character'); } }
      },
    };
  }

  return { TYPES, EXT, LABEL, MP4_BRANDS, PDF_WINDOW, sniff, validator };
});
