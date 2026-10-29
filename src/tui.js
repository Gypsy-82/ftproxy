'use strict';
// Host-side terminal UI. ASCII-only, colour via ANSI (see render.js).
// Every string that originated with the guest — chat, filenames, reasons — is
// passed through sanitize() before it touches the terminal, because the
// terminal EXECUTES escape sequences (see sanitize.js).
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const r = require('./render');
const { sanitize } = require('./sanitize');
const { LABEL } = require('./shared/filetype');
const { sendPath } = require('./transfer');
const { expandHome } = require('./hostfile');
const picker = require('./picker');

const mib = (n) => (n < 1048576 ? (n / 1024).toFixed(1) + ' KiB' : (n / 1048576).toFixed(1) + ' MiB');
const S = (s) => sanitize(String(s == null ? '' : s));

function bar(frac, width = 20) {
  const n = Math.max(0, Math.min(width, Math.round(frac * width)));
  return '[' + '#'.repeat(n) + '.'.repeat(width - n) + ']';
}

// Tab-completes paths after "/send ".
function completer(line) {
  const m = /^\/send\s+(?:--keep-meta\s+)?(.*)$/.exec(line);
  if (!m) return [[], line];
  const typed = m[1];
  const exp = expandHome(typed || './');
  const dir = typed.endsWith('/') ? exp : path.dirname(exp);
  const base = typed.endsWith('/') ? '' : path.basename(exp);
  let names = [];
  // Dotfiles only appear once you've typed the dot.
  try { names = fs.readdirSync(dir, { withFileTypes: true }).filter((d) => d.name.startsWith(base) && (base.startsWith('.') || !d.name.startsWith('.'))); } catch {}
  const prefix = typed.slice(0, typed.length - base.length);
  const hits = names.map((d) => prefix + d.name + (d.isDirectory() ? '/' : ''));
  return [hits.map((h) => line.slice(0, line.length - typed.length) + h), line];
}

// Shown when the guest connects: sending is otherwise only in /help.
function sendHint() {
  return '  ' + r.C.dim('to send them a file: ') + r.C.cyan('/send') + r.C.dim(' (opens a file picker), ') +
    r.C.cyan('/send <path>') + r.C.dim(', or type /send and drag a file here');
}

class Tui {
  constructor(relay, engine, { onQuit, link, ttlMin, mode, safety, inbox, keepMeta }) {
    this.relay = relay;
    this.engine = engine;
    this.onQuit = onQuit;
    this.link = link;
    this.ttlMin = ttlMin;
    this.mode = mode || '';
    this.safety = safety || '';
    this.inbox = inbox;
    this.keepMeta = !!keepMeta;
    this.lastProg = new Map();
    this.picking = null;                      // the open file dialog, if any
    this.findPicker = picker.findPicker;
    this.pickFile = picker.pickFile;
    this.rl = readline.createInterface({ input: process.stdin, output: process.stdout, completer });
  }

  start() {
    this.rl.setPrompt(r.C.green('> '));
    this._raw('\n' + r.banner({ ttlMin: this.ttlMin, mode: this.mode, safety: this.safety }) + '\n');
    this._raw(r.system('waiting for the guest to open the link') + '\n');
    this._raw('  ' + r.C.dim('inbox: ' + this.inbox.dir) + '\n');

    const relay = this.relay, e = this.engine;
    relay.on('client-online', () => this._event(r.system('guest connected') + '\n' + r.keyLine(true, this.safety) + '\n' + sendHint()));
    relay.on('client-offline', () => this._event(r.system('guest disconnected')));
    relay.on('tamper', (why) => this._keyAlarm(S(why)));
    relay.on('auth-fail', (n) => this._event(r.system(r.C.red(`! bad-key attempt ${n}/${relay.maxFails}`))));
    relay.on('takeover-blocked', (n) => this._event(r.system(r.C.red(`! blocked a takeover of the held seat ${n}/${relay.maxFails}`))));
    relay.on('transfer-strike', (n) => this._event(r.system(r.C.red(`! bad transfer from the guest ${n}/${relay.maxFails}`))));

    e.on('chat', (text) => this._event(r.bubble({ text: S(text), side: 'left' })));
    e.on('offer', (v) => this._event(this._offerCard(v)));
    e.on('outgoing', (v) => this._event(r.system(`offered ${S(v.name)} (${mib(v.size)}) - waiting for them to accept`)));
    e.on('progress', (v) => this._progress(v));
    e.on('state', (v) => {
      if (v.state === 'paused') this._event(r.system(`${S(v.name)}: paused, waiting for the guest to reconnect`));
      else if (v.state === 'streaming' && v.dir === 'out' && v.next === 0) this._event(r.system(`they accepted ${S(v.name)} - sending`));
      else if (v.state === 'declined') this._event(r.system(v.dir === 'out' ? `they declined ${S(v.name)}${v.reason && v.reason !== 'declined' ? ' (' + S(v.reason) + ')' : ''}` : `declined ${S(v.name)}`));
      else if (v.state === 'expired') this._event(r.system(`offer for ${S(v.name)} expired`));
    });
    e.on('done', (v, savedPath) => {
      if (v.dir === 'in') {
        this._event(
          '  ' + r.C.green('* received + verified ') + S(v.name) + '\n' +
          '    ' + r.C.cyan(S(savedPath)) + '\n' +
          '    ' + r.C.dim(`${mib(v.size)}  sha256 ${v.sha256}`) + '\n' +
          '    ' + r.C.dim('not opened. treat it as untrusted - open in a patched or sandboxed viewer.'));
      } else {
        this._event('  ' + r.C.green('* delivered ') + S(v.name) + r.C.dim('  - the guest verified the fingerprint'));
      }
    });
    e.on('failed', (v, why) => this._event('  ' + r.C.red('x transfer failed: ') + S(v.name) + r.C.dim(' - ' + S(why) + (v.dir === 'in' ? ' (partial deleted)' : ''))));
    e.on('error', (err) => this._event(r.system(r.C.red('internal error: ' + S(err && err.message)))));

    this.rl.on('line', (line) => this._onLine(line));
    this.rl.on('SIGINT', () => this._quit());
    this.rl.prompt();
  }

  _offerCard(v) {
    const w = Math.min(r.WIDTH(), 72);
    const line = (s) => '  | ' + s;
    return [
      '  +' + '-'.repeat(w - 4),
      line(r.C.greenB('INCOMING FILE')),
      line(S(v.name)),
      line(r.C.dim(`${mib(v.size)}  ${LABEL[v.type]}  sha256 ${v.sha256.slice(0, 8)}${v.stripped ? '  photo metadata removed' : ''}`)),
      line(r.C.cyan('/accept') + '  or  ' + r.C.cyan('/decline') + r.C.dim('   (expires in 2 min)')),
      '  +' + '-'.repeat(w - 4),
    ].join('\n');
  }

  _progress(v) {
    const now = Date.now();
    const last = this.lastProg.get(v.id) || { t: v.started || now, b: 0, pct: -10, rate: 0 };
    const frac = v.size ? v.bytes / v.size : 1;
    const pct = Math.floor(frac * 100);
    if (pct < last.pct + 10 && now - last.t < 3000 && pct < 100) return;
    const dt = (now - last.t) / 1000;
    const rate = dt > 0 ? (v.bytes - last.b) / dt : last.rate;
    const eta = rate > 0 ? Math.ceil((v.size - v.bytes) / rate) : 0;
    this.lastProg.set(v.id, { t: now, b: v.bytes, pct, rate });
    this._event('  ' + r.C.dim(v.dir === 'in' ? 'recv ' : 'send ') + bar(frac) + ` ${String(pct).padStart(3)}%  ${mib(v.bytes)}/${mib(v.size)}  ${mib(rate)}/s` + (eta && pct < 100 ? `  eta ${eta}s` : ''));
  }

  _onLine(line) {
    const text = line.replace(/\r?\n$/, '');
    const trimmed = text.trim();
    if (!trimmed) { this.rl.prompt(); return; }
    if (trimmed.startsWith('/')) return this._command(trimmed);
    readline.moveCursor(process.stdout, 0, -1);
    readline.clearLine(process.stdout, 0);
    if (!this.relay.hasClient()) { this._sys(r.C.gray('no guest connected - not sent')); this.rl.prompt(true); return; }
    // Echo exactly what the far side gets, scrubbed, so a pasted escape
    // sequence can't hit our own terminal either.
    const clean = S(text);
    process.stdout.write(r.bubble({ text: clean, side: 'right' }) + '\n');
    this.engine.chat(clean);
    this.rl.prompt(true);
  }

  async _command(text) {
    const cmd0 = text.slice(1).split(/\s+/)[0];
    const cmd = cmd0.toLowerCase();
    const arg = text.slice(1 + cmd0.length).trim();
    readline.moveCursor(process.stdout, 0, -1);
    readline.clearLine(process.stdout, 0);
    try {
      if (cmd === 'quit' || cmd === 'q' || cmd === 'exit') return this._quit();
      if (cmd === 'send') await this._send(arg);
      else if (cmd === 'accept' || cmd === 'a') { if (!(await this.engine.accept())) this._sys('no incoming offer to accept'); }
      else if (cmd === 'decline' || cmd === 'd') { if (!(await this.engine.decline())) this._sys('no incoming offer to decline'); }
      else if (cmd === 'cancel') { const n = await this.engine.cancel(); this._sys(n ? `cancelled ${n} transfer(s)` : 'nothing to cancel'); }
      else if (cmd === 'files') this._files();
      else if (cmd === 'status') this._sys(this.relay.hasClient() ? 'guest connected' : 'waiting for guest');
      else if (cmd === 'link') process.stdout.write('\n     ' + r.C.cyan(this.link) + '\n');
      else if (cmd === 'qr') process.stdout.write('\n' + r.qrBlock(this.link) + '\n');
      else if (cmd === 'share')process.stdout.write('\n' + r.shareBlock({ link: this.link, safety: this.safety }) + '\n');
      else if (cmd === 'safety') this._sys(`safety code ${r.C.green(this.safety)} - read it to your contact; it must match their screen`);
      else if (cmd === 'clear') { console.clear(); this._raw(r.banner({ ttlMin: this.ttlMin, mode: this.mode, safety: this.safety }) + '\n'); }
      else if (cmd === 'help') this._legend();
      else this._sys(`unknown command: /${S(cmd)}  (try /help)`);
    } catch (e) {
      this._sys(r.C.red('! ' + S(e.message)));
    }
    this.rl.prompt();
  }

  async _send(arg) {
    let keepMeta = this.keepMeta;
    let p = arg;
    if (p.startsWith('--keep-meta')) { keepMeta = true; p = p.slice('--keep-meta'.length).trim(); }
    if (/^(['"]).*\1$/.test(p)) p = p.slice(1, -1);       // allow a quoted (or dragged-in) path with spaces
    if (!this.relay.hasClient()) { this._sys('no guest connected yet'); return; }
    if (!p) {
      // Bare /send: open the desktop's own file dialog, if there is one.
      if (this.picking) { this._sys('a file picker is already open'); return; }
      const pk = this.findPicker();
      if (!pk) { this._sys('usage: /send [--keep-meta] <path>  ' + r.C.dim('(or drag a file into this window)')); return; }
      this._sys('opening a file picker...');
      this.picking = this.pickFile(pk);
      try { p = await this.picking.promise; } finally { this.picking = null; }
      if (!p) { this._sys('no file chosen'); return; }
      if (!this.relay.hasClient()) { this._sys('guest disconnected - not sent'); return; }
    }
    this._sys(`checking + fingerprinting ${S(path.basename(p))}...`);
    const { warn } = await sendPath(this.engine, p, { keepMeta });
    if (warn) this._sys(r.C.dim(S(warn)));
  }

  _files() {
    const s = this.engine.status();
    const all = [...s.history, ...[s.out, s.inc].filter((t) => t && !s.history.find((h) => h.id === t.id))];
    if (!all.length) { this._sys('no transfers yet'); return; }
    for (const t of all) {
      const where = t.dir === 'in' && t.result ? '  ' + r.C.cyan(S(t.result)) : '';
      const pct = t.size ? Math.floor((t.bytes / t.size) * 100) : 100;
      this._raw(`  ${t.dir === 'in' ? 'in ' : 'out'}  ${t.state.padEnd(9)} ${String(pct).padStart(3)}%  ${S(t.name)}  ${r.C.dim(mib(t.size))}${where}${t.reason ? r.C.dim('  - ' + S(t.reason)) : ''}`);
    }
  }

  _sys(msg) { process.stdout.write(r.system(msg) + '\n'); }

  _legend() {
    const L = (s) => process.stdout.write(s + '\n');
    L(r.system('commands'));
    L('  ' + r.C.cyan('/send [path]') + r.C.dim('       offer a file: no path opens a file picker; tab completes; drag-drop works'));
    L('  ' + r.C.dim('                     --keep-meta keeps JPEG metadata'));
    L('  ' + r.C.cyan('/accept /decline') + r.C.dim('   answer an incoming offer  (/a /d)'));
    L('  ' + r.C.cyan('/cancel') + r.C.dim('            abort active transfers (partials deleted)'));
    L('  ' + r.C.cyan('/files') + r.C.dim('             this session\'s transfers and where they were saved'));
    L('  ' + r.C.cyan('/qr') + r.C.dim('                the link as a QR code for a phone camera'));
    L('  ' + r.C.cyan('/safety /link /share /status /clear /quit'));
    L('  ' + r.C.dim('allowed: .txt .png .jpg .mp4 .pdf up to 500 MiB - type is checked from the bytes'));
  }

  _keyAlarm(why) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
    process.stdout.write('\n' + r.keyLine(false) + '\n' + r.alarm('KEYS CHANGED - ' + why) + '\n');
  }

  _event(block) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
    process.stdout.write(block + '\n');
    this.rl.prompt(true);
  }

  _raw(s) { process.stdout.write(s + '\n'); }

  _quit() {
    this._raw('');
    process.stdout.write(r.system('shutting down - destroying link, deleting partials...') + '\n');
    if (this.picking) this.picking.kill();
    this.rl.close();
    this.onQuit();
  }
}

module.exports = { Tui, completer, bar, sendHint };
