#!/usr/bin/env node
'use strict';
// ftproxy launcher. New random token + keys every launch; the link
// self-destructs on Ctrl+C, /quit, guest-leave, tripwire, tamper, or TTL —
// and every partial file is deleted when it does.

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const c = require('../src/crypto');
const r = require('../src/render');
const colors = require('../src/colors');
const { Relay } = require('../src/server');
const { Tui } = require('../src/tui');
const { Inbox, defaultInbox } = require('../src/fsafe');
const { createHostEngine } = require('../src/transfer');
const caddy = require('../src/caddy');
const tunnel = require('../src/tunnel');
const preflight = require('../src/preflight');
const pkg = require('../package.json');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}
function hasCmd(cmd) {
  return (process.env.PATH || '').split(path.delimiter).some((d) => {
    try { fs.accessSync(path.join(d, cmd), fs.constants.X_OK); return true; } catch { return false; }
  });
}
// Best-effort copy of the link so terminal line-wrapping can't break it.
function copyToClipboard(text) {
  for (const [cmd, args] of [['termux-clipboard-set', []], ['wl-copy', []], ['xclip', ['-selection', 'clipboard']], ['xsel', ['--clipboard', '--input']]]) {
    if (!hasCmd(cmd)) continue;
    try {
      const child = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'] });
      const t = setTimeout(() => { try { child.kill(); } catch {} }, 1200);
      child.on('error', () => clearTimeout(t)); child.on('exit', () => clearTimeout(t));
      child.stdin.on('error', () => {}); child.stdin.end(text);
      return true;
    } catch {}
  }
  return false;
}
function looksLocal(addr) {
  const a = String(addr).toLowerCase().split(':')[0];
  if (a === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(a) || !a.includes('.')) return true;
  return /\.(local|test|lan|internal|home|localhost)$/.test(a);
}

function printHelp() {
  const g = r.C.green, d = r.C.dim, c2 = r.C.cyan;
  const L = (s) => process.stdout.write(s + '\n');
  L('');
  L('  ' + g('ftproxy') + d('  private end-to-end encrypted 1:1 file transfer  v' + pkg.version));
  L('');
  L('  ' + c2('ftproxy') + '                   start: Cloudflare quick tunnel + Caddy, one link');
  L('  ' + c2('ftproxy --doctor') + '          check caddy / cloudflared');
  L('');
  L('  ' + c2('--inbox <dir>') + '     where guest files land  ' + d('(default ' + defaultInbox() + ')'));
  L('  ' + c2('--keep-meta') + '       do NOT strip JPEG metadata on /send  ' + d('(default: strip)'));
  L('  ' + c2('--ttl <min>') + ' ' + d('[90]') + '  ' + c2('--fails <n>') + ' ' + d('[3]') + '  ' + c2('--grace <sec>') + ' ' + d('[45]') + '  ' + c2('--port <n>'));
  L('  ' + c2('--qr') + '              also show the link as a QR code  ' + d('(or /qr in session)'));
  L('  ' + c2('--local') + ' ' + d('[--domain host]') + '   ' + c2('--no-caddy') + '   ' + c2('--no-burn') + '   ' + c2('--short'));
  L('');
  L('  ' + d('In session') + '  /send [path]  /accept  /decline  /cancel  /files  /safety  /help  /quit');
  L('  ' + d('Allowed') + '     .txt .png .jpg .mp4 .pdf, max 500 MiB, type verified from the bytes');
  L('  ' + d('Security') + '    AES-256-GCM end to end; key only in the link #fragment; tamper -> burn');
  L('');
}

function doctor() {
  const s = preflight.check();
  const mark = (b) => (b ? r.C.green('ok') : r.C.red('XX'));
  const L = (x) => process.stdout.write(x + '\n');
  L('\n  ' + r.C.green('ftproxy - doctor') + r.C.dim(`   platform: ${s.platform}`) + '\n');
  L(`    ${mark(s.node.ok)} node ${s.node.version}` + (s.node.ok ? '' : r.C.dim(`  (need ${s.node.need})`)));
  L(`    ${mark(s.caddy.ok)} caddy` + (s.caddy.ok ? '' : r.C.dim(`   -> ${s.caddy.hint}`)));
  L(`    ${mark(s.cloudflared.ok)} cloudflared` + (s.cloudflared.ok ? '' : r.C.dim(`   (needed unless you use --local) -> ${s.cloudflared.hint}`)));
  L('');
}

function configFromFlags(argv) {
  const has = (f) => argv.includes(f);
  const opt = (f, d) => { const i = argv.indexOf(f); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
  const int = (f, d) => { const v = parseInt(opt(f, String(d)), 10); return Number.isFinite(v) && v >= 0 ? v : d; };
  const portArg = opt('--port', 'auto');
  const domain = opt('--domain', 'localhost');
  return {
    reach: has('--local') ? 'local' : 'tunnel',
    port: /^\d+$/.test(portArg) ? parseInt(portArg, 10) : 0,
    ttlMin: Math.max(1, int('--ttl', 90)),
    maxFails: Math.max(1, int('--fails', 3)),
    graceSec: int('--grace', 45),
    runCaddy: !has('--no-caddy'),
    burnOnDisconnect: !has('--no-burn'),
    tokenBytes: has('--short') ? 12 : 24,
    inbox: opt('--inbox', defaultInbox()),
    keepMeta: has('--keep-meta'),
    qr: has('--qr'),
    domain, tlsMode: looksLocal(domain) ? 'internal' : 'le', lease: '168h', email: '',
  };
}

async function launch(cfg) {
  r.setColors(colors.load());
  const pf = preflight.check();
  const need = [];
  if (cfg.runCaddy && !pf.caddy.ok) need.push('caddy');
  if (cfg.reach === 'tunnel' && !pf.cloudflared.ok) need.push('cloudflared');
  if (need.length) {
    console.log('\n  First run - fetching ' + need.join(' + ') + ' for your platform...');
    spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'fetch-deps.js')], { stdio: 'inherit' });
  }

  // Inbox first: if it's unsafe (symlink, loose perms) refuse before any link exists.
  let inbox;
  try { inbox = new Inbox(cfg.inbox); } catch (e) { console.error('\n  ' + r.C.red('! ' + e.message) + '\n'); process.exit(1); }
  const swept = inbox.sweep();

  // <token> addresses the room; the fragment key unlocks it. Browsers never
  // send a fragment, so nothing between the two endpoints ever sees it.
  const token = c.randomB64u(cfg.tokenBytes);
  const secret = c.newSessionKey();
  const salt = c.randomB64u(16);
  const keys = await c.deriveKeys(secret, salt);
  const sas = await c.safetyCode(keys.macKey);

  const relay = new Relay({ token, salt, keys, port: cfg.port, maxFails: cfg.maxFails, burnOnDisconnect: cfg.burnOnDisconnect, graceSec: cfg.graceSec });
  const engine = await createHostEngine({ relay, secret: c.fromB64u(secret), encKey: keys.encKey, inbox });
  const boundPort = await relay.listen();

  let caddyChild = null, caddyfilePath = null, tunnelChild = null, link, mode;
  const killChildren = () => {
    for (const ch of [caddyChild, tunnelChild]) if (ch) { try { ch.kill('SIGTERM'); } catch {} }
  };
  const warnCaddy = (e) => console.error('\n  [caddy] could not start: ' + e.message + '\n');

  if (cfg.reach === 'tunnel') {
    let origin = `http://127.0.0.1:${boundPort}`;
    if (cfg.runCaddy) {
      const caddyPort = await getFreePort();
      caddyfilePath = caddy.writeCaddyfile(caddy.renderCaddyfile({ domain: `:${caddyPort}`, port: boundPort, tlsMode: 'le', lease: cfg.lease, email: '' }));
      caddyChild = caddy.startCaddy(caddyfilePath);
      caddyChild.on('error', warnCaddy);
      origin = `http://127.0.0.1:${caddyPort}`;
    }
    console.log('\n  Starting Cloudflare quick tunnel...');
    try {
      const t = await tunnel.startTunnel(origin);
      tunnelChild = t.child;
      link = `${t.url}/r/${token}#k=${secret}`;
      mode = `cloudflare tunnel${cfg.runCaddy ? ' - caddy' : ''}`;
    } catch (e) {
      console.error('  [tunnel] ' + e.message + '\n  Get cloudflared with ./install.sh  (or see --doctor)');
      relay.destroy(); engine.destroy(); killChildren();
      if (caddyfilePath) { try { fs.unlinkSync(caddyfilePath); } catch {} }
      process.exit(1);
    }
  } else {
    caddyfilePath = caddy.writeCaddyfile(caddy.renderCaddyfile({ domain: cfg.domain, port: boundPort, tlsMode: cfg.tlsMode, lease: cfg.lease, email: cfg.email }));
    if (cfg.runCaddy) { caddyChild = caddy.startCaddy(caddyfilePath); caddyChild.on('error', warnCaddy); }
    link = `https://${cfg.domain}/r/${token}#k=${secret}`;
    mode = `${cfg.tlsMode === 'internal' ? 'self-signed' : "Let's Encrypt"} - ${cfg.domain}`;
  }

  let destroyed = false;
  const destroy = (why) => {
    if (destroyed) return;
    destroyed = true;
    clearTimeout(ttlTimer);
    if (why) console.log('\n  Self-destruct: ' + why);
    engine.destroy();                 // deletes any .part file synchronously
    try { relay.destroy(); } catch {}
    killChildren();
    if (caddyfilePath) { try { fs.unlinkSync(caddyfilePath); } catch {} }
    console.log('  Link destroyed. Partial files deleted; finished files are in ' + inbox.dir + '\n');
    process.exit(0);
  };
  const ttlTimer = setTimeout(() => destroy(`lifetime reached (${cfg.ttlMin} min)`), cfg.ttlMin * 60 * 1000);
  relay.on('selfdestruct', (why) => destroy(why));
  process.on('SIGTERM', () => destroy('terminated'));
  process.on('SIGHUP', () => destroy('terminal closed'));
  process.on('exit', () => { engine.destroy(); killChildren(); });

  console.log('\n' + r.shareBlock({ link, safety: sas }));
  if (cfg.qr) console.log('\n' + r.qrBlock(link) + '\n');
  if (copyToClipboard(link)) console.log('  ' + r.C.green('link copied to your clipboard') + r.C.dim(' - just paste it into a message'));
  if (swept) console.log('  ' + r.C.dim(`cleaned up ${swept} partial file(s) from a previous run`));
  if (!cfg.runCaddy && cfg.reach === 'local') console.log('\n  ' + r.C.dim('Caddy not started - run it yourself: caddy run --config ' + caddyfilePath));

  new Tui(relay, engine, { link, ttlMin: cfg.ttlMin, mode, safety: sas, inbox, keepMeta: cfg.keepMeta, onQuit: () => destroy('host quit') }).start();
}

// Piping --help into head etc. closes stdout early; that's not an error.
process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(0); throw e; });

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) return printHelp();
  if (argv.includes('--version') || argv.includes('-v')) return console.log(pkg.version);
  if (argv.includes('--doctor')) return doctor();
  return launch(configFromFlags(argv));
}

main().catch((e) => { console.error(e); process.exit(1); });
