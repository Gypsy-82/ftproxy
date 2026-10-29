'use strict';
// Text arriving from the other party is untrusted BYTES, not merely "a string".
//
// The browser half of this tool is safe by construction: both pages render with
// textContent and never innerHTML, so markup and script are inert there. The
// TERMINAL half is not, because a terminal emulator *executes* control sequences
// it is handed. Without this filter a chat message can:
//
//   OSC 52  -> silently rewrite the operator's system clipboard, so the next
//              thing they paste into a shell is attacker-chosen text
//   OSC 8   -> render "totally-safe-link" that actually points at evil.example
//   OSC 0   -> rewrite the terminal's window title
//   CSI A/J/K -> move the cursor and overwrite lines the message doesn't own,
//              e.g. forging output above itself
//   \r      -> return to column 0 and overprint the line
//
// None of that is code execution inside Node — nothing is ever eval'd — but it
// is code execution *by the terminal*, and the clipboard path turns it into a
// plausible route to a shell. So we strip it where the trust boundary actually
// is: on every message crossing between the two endpoints, in both directions.
//
// Kept:    \n, because multi-line messages are a feature (shift+enter).
// Folded:  \t -> four spaces, so alignment can't be abused but text survives.
// Dropped: every other C0 control, DEL, the whole C1 range, and the Unicode
//          bidi overrides behind "Trojan Source" style display spoofing.

const CONTROLS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g; // C0 minus \t\n, DEL, C1
const BIDI = /[‎‏‪-‮⁦-⁩]/g;

function sanitize(text) {
  return String(text)
    .replace(/\t/g, '    ')
    .replace(CONTROLS, '')
    .replace(BIDI, '');
}

module.exports = { sanitize };
