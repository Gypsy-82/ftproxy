// Lossless JPEG metadata strip (DESIGN.md §11). Walks the segment structure
// from SOI; never re-encodes, so pixels are bit-identical.
//
//   KEEP  APP0 (JFIF), APP2 ICC_PROFILE (colour), APP14 (Adobe — needed to
//         decode CMYK correctly), DQT/DHT/SOF/DRI/SOS and the entropy data.
//   DROP  APP1 (Exif, XMP — GPS lives here), APP3–APP13 (incl. APP13
//         IPTC/Photoshop), APP15, COM comments, APP2 "MPF" (multi-picture
//         index), and EVERYTHING after the first EOI.
//
// That last rule goes beyond the spec on purpose: phones append MPF secondary
// images (depth maps, previews) after EOI, and those carry their OWN Exif with
// the same GPS fix. Stripping APP1 alone would leave the location in the file.
//
// Anything structurally unexpected throws — the caller then asks the user to
// send as-is rather than guessing. Fail closed.
//
// ISOMORPHIC: runs in Node and is inlined verbatim into the guest page.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('exif', function () {
  'use strict';

  const STRIP_LIMIT = 50 * 1024 * 1024;     // larger JPEGs are sent as-is with a warning

  function malformed(why) { return new Error('malformed JPEG: ' + why); }
  function idIs(p, s) {                     // segment identifier, after the 2 length bytes
    if (p.length < 2 + s.length) return false;
    for (let i = 0; i < s.length; i++) if (p[2 + i] !== s.charCodeAt(i)) return false;
    return true;
  }
  function dropSegment(m, p) {
    if (m === 0xe1) return true;                          // APP1  Exif / XMP
    if (m >= 0xe3 && m <= 0xed) return true;              // APP3..APP13 (APP13 = IPTC)
    if (m === 0xef) return true;                          // APP15
    if (m === 0xfe) return true;                          // COM
    if (m === 0xe2 && idIs(p, 'MPF\0')) return true;      // multi-picture index
    return false;
  }

  // Returns { bytes, removed } — removed = number of bytes dropped.
  function strip(b) {
    if (!(b instanceof Uint8Array) || b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) throw malformed('no SOI');
    const out = [b.subarray(0, 2)];
    let kept = 2;
    let i = 2;
    for (;;) {
      if (i >= b.length) throw malformed('missing EOI');
      if (b[i] !== 0xff) throw malformed('expected a marker');
      while (i < b.length && b[i] === 0xff) i++;          // fill bytes
      if (i >= b.length) throw malformed('truncated marker');
      const m = b[i++];

      if (m === 0xd9) { out.push(new Uint8Array([0xff, 0xd9])); kept += 2; break; }   // EOI: stop here
      if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) {        // standalone markers, no length
        out.push(new Uint8Array([0xff, m])); kept += 2; continue;
      }
      if (m === 0x00 || m === 0xd8) throw malformed('unexpected marker');
      if (i + 2 > b.length) throw malformed('truncated length');
      const len = (b[i] << 8) | b[i + 1];
      if (len < 2 || i + len > b.length) throw malformed('segment overruns file');
      const payload = b.subarray(i, i + len);
      i += len;
      if (!dropSegment(m, payload)) { out.push(new Uint8Array([0xff, m]), payload); kept += 2 + len; }

      if (m === 0xda) {                                    // SOS: entropy-coded data follows
        const start = i;
        while (i < b.length) {
          if (b[i] === 0xff) {
            const n = b[i + 1];
            if (n === 0x00 || (n >= 0xd0 && n <= 0xd7)) { i += 2; continue; }   // stuffing / RSTn
            break;                                         // a real marker (or fill)
          }
          i++;
        }
        if (i >= b.length) throw malformed('scan runs off the end');
        out.push(b.subarray(start, i)); kept += i - start;
      }
    }
    const bytes = new Uint8Array(kept);
    let o = 0;
    for (const p of out) { bytes.set(p, o); o += p.length; }
    return { bytes, removed: b.length - kept };
  }

  return { strip, STRIP_LIMIT };
});
