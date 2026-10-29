'use strict';
// HTTP + WebSocket endpoint. Serves the single guest page at /r/<token>, and
// bridges ONE authenticated browser to the host's transfer engine.
//
// Containment / hardening (inherited from SMSproxy):
//   * Binds 127.0.0.1 only — never directly reachable; Caddy is the sole front.
//   * Only the exact /r/<token> path returns anything; all else is 404. No file
//     serving at all, so the link can't be used to read the filesystem.
//   * Single session; HMAC challenge/response auth; tripwire; burn-after-session;
//     the grace window only re-admits the holder of the one-time reconnect ticket.
//
// New for ftproxy:
//   * Connection binding. The guest sends a fresh 16-byte nonce with its auth;
//     binding = challenge(32) ‖ nonce(16) goes into the AAD of every control
//     envelope (see shared/stream-crypto.js). Both halves are fresh, so traffic
//     recorded on one connection can't be replayed into another — in EITHER
//     direction.
//   * Binary frames are accepted only from the authed active connection.
//     Anything else gets 1008 and is gone.
//   * No plaintext app messages any more: chat, offers, acks all ride inside the
//     encrypted, sequenced envelope. The only plaintext left is the handshake
//     and burn/tamper signals, which an attacker can at most use to end the
//     session — never to read or alter a file.
//   * Origin check on the upgrade, and a per-request CSP that pins the inline
//     script/style by hash and connect-src to this exact host.

const http = require('http');
const { EventEmitter } = require('events');
const { timingSafeEqual } = require('crypto');
const wslite = require('./wslite');
const c = require('./crypto');
const { buildPage } = require('./page');

const MAX_PENDING = 4; // unauthenticated sockets held at once
const HOST_RE = /^[a-z0-9.-]{1,253}(:\d{1,5})?$/i;

class Relay extends EventEmitter {
  constructor({ token, salt, keys, port = 0, maxFails = 10, burnOnDisconnect = true, graceSec = 30, heartbeatSec = 15 }) {
    super();
    this.token = token;
    this.salt = salt;
    this.keys = keys;
    this.port = port; // 0 => OS picks a free port
    this.maxFails = maxFails;
    this.burnOnDisconnect = burnOnDisconnect;
    this.graceSec = graceSec;
    this.heartbeatMs = heartbeatSec * 1000;

    this.basePath = `/r/${token}`;
    this.active = null;
    this.pending = new Set();
    this.everConnected = false;   // has anyone ever held this room?
    this.reconnectToken = null;   // one-time ticket back in, held by that client only
    this.failCount = 0;
    this.tampered = false;
    this.graceTimer = null;
    this.destroyed = false;
    const page = buildPage();
    this.index = page.html;
    this.scriptHash = page.scriptHash;
    this.styleHash = page.styleHash;

    this.server = http.createServer((req, res) => this._onHttp(req, res));
    this.server.on('upgrade', (req, sock, head) => this._onUpgrade(req, sock, head));
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, '127.0.0.1', () => {
        this.port = this.server.address().port;
        resolve(this.port);
      });
    });
  }

  csp(host) {
    const ws = HOST_RE.test(host || '') ? ` wss://${host} ws://${host}` : '';
    return [
      "default-src 'none'",
      `script-src ${this.scriptHash}`,
      `style-src ${this.styleHash}`,
      'img-src blob:',                       // verified png/jpeg previews only
      `connect-src 'self'${ws}`,
      "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
    ].join('; ');
  }

  _onHttp(req, res) {
    const url = (req.url || '').split('?')[0];
    if (req.method === 'GET' && (url === this.basePath || url === this.basePath + '/')) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': this.csp(req.headers.host),
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',        // the token path must never leak in a Referer
        'x-frame-options': 'DENY',
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-resource-policy': 'same-origin',
        'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      });
      res.end(this.index);
      return;
    }
    if (req.method === 'GET' && url === '/favicon.ico') { res.writeHead(204); res.end(); return; }
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('not found\n');
  }

  _onUpgrade(req, socket, head) {
    const url = (req.url || '').split('?')[0];
    if (this.destroyed || url !== this.basePath + '/ws') { socket.destroy(); return; }
    // A browser always sends Origin on a WS upgrade. If it names another site,
    // some page is trying to grab the seat from the guest's browser — refuse.
    const origin = req.headers.origin;
    if (origin) {
      let oh = '';
      try { oh = new URL(origin).host; } catch {}
      if (!oh || oh.toLowerCase() !== String(req.headers.host || '').toLowerCase()) { socket.destroy(); return; }
    }

    if (this.active || this.pending.size >= MAX_PENDING) {
      const conn = wslite.accept(req, socket, head);
      if (conn) { conn.send(JSON.stringify({ t: 'busy' })); conn.close(1013, 'session in use'); }
      return;
    }
    const conn = wslite.accept(req, socket, head);
    if (conn) this._onClient(conn);
  }

  _strike(event) {
    this.failCount += 1;
    this.emit(event, this.failCount);
    if (this.failCount >= this.maxFails) this.emit('selfdestruct', `${this.failCount} failed attempts / bad transfers`);
  }

  // Count an authenticated peer's bad transfer (type/size/hash) toward the tripwire.
  strike(reason) { this._strike('transfer-strike'); this.emit('strike-reason', reason); }

  _onClient(conn) {
    conn.authed = false;
    conn.challenge = c.randomB64u(32);
    this.pending.add(conn);

    const authTimer = setTimeout(() => { if (!conn.authed) conn.close(4001, 'auth timeout'); }, 15000);

    conn.send(JSON.stringify({ t: 'hello', salt: this.salt, challenge: conn.challenge }));

    conn.on('binary', (buf) => {
      if (!conn.authed || conn !== this.active) return conn.close(1008, 'unexpected binary');
      this.emit('binary', new Uint8Array(buf.buffer, buf.byteOffset, buf.length));
    });

    conn.on('message', async (raw) => {
      let m;
      try { m = JSON.parse(raw); } catch { return; }
      if (!m || typeof m !== 'object') return;

      if (m.t === 'auth' && !conn.authed) {
        const ok = await this._verify(conn.challenge, m.proof);
        let cn = null;
        try { cn = c.fromB64u(m.cn); } catch {}
        if (!ok || !cn || cn.length !== 16) {
          conn.send(JSON.stringify({ t: 'auth-fail' }));
          conn.close(4003, 'bad key');
          this._strike('auth-fail');
          return;
        }
        if (this.active) { conn.send(JSON.stringify({ t: 'busy' })); conn.close(1013, 'session in use'); return; }
        // Holding the key is enough to OPEN the room, but not to STEAL it back.
        // While the grace timer keeps a dropped client's seat warm, only that
        // client — the one holding the one-time reconnect token — may sit down.
        if (this.everConnected && this.graceTimer && !this._verifyReconnect(m.reconnect)) {
          conn.send(JSON.stringify({ t: 'busy' }));
          conn.close(1013, 'seat held for the previous client');
          this._strike('takeover-blocked');
          return;
        }
        conn.authed = true;
        this.pending.delete(conn);
        this.active = conn;
        this.everConnected = true;
        clearTimeout(authTimer);
        if (this.graceTimer) { clearTimeout(this.graceTimer); this.graceTimer = null; }
        // Fresh ticket every time, so a captured one is useless after it is used.
        this.reconnectToken = c.randomB64u(24);
        const bind = new Uint8Array(48);
        bind.set(c.fromB64u(conn.challenge), 0);
        bind.set(cn, 32);
        conn.on('drain', () => this.emit('drain'));
        // A phone that vanishes (tab killed, battery, network) often sends no
        // close frame, and the tunnel keeps its end open, so 'close' would never
        // fire. App-level pings (proxies may eat control frames): two silent
        // intervals and the socket is cut, which starts the grace -> burn path.
        conn.hb = setInterval(() => {
          if (Date.now() - conn.lastSeen > 2 * this.heartbeatMs) conn.terminate();
          else conn.send('{"t":"ping"}');
        }, this.heartbeatMs);
        conn.send(JSON.stringify({ t: 'auth-ok', reconnect: this.reconnectToken }));
        this.emit('client-online', bind);
      } else if (m.t === 'x' && conn.authed && conn === this.active) {
        this.emit('envelope', m);
      } else if (m.t === 'tamper' && conn.authed && conn === this.active) {
        this._tamper('the guest detected a key change or tampering');
      } else if (m.t === 'bye' && conn.authed && conn === this.active) {
        // The guest closed or left the page. No reconnect is coming, so the
        // grace window would only keep a dead link alive: burn now.
        if (this.burnOnDisconnect) this.emit('selfdestruct', 'the guest closed the page');
        else conn.close(1000, 'guest left');
      }
    });

    conn.on('close', () => {
      clearTimeout(authTimer);
      clearInterval(conn.hb);
      this.pending.delete(conn);
      if (conn === this.active) {
        this.active = null;
        this.emit('drain');                     // release a sender blocked on backpressure
        this.emit('client-offline');
        if (this.burnOnDisconnect && !this.destroyed) {
          if (this.graceSec <= 0) {
            this.emit('selfdestruct', 'client left');
          } else {
            this.graceTimer = setTimeout(() => this.emit('selfdestruct', 'client left'), this.graceSec * 1000);
          }
        }
      }
    });
  }

  // Constant-time check of the one-time reconnect ticket.
  _verifyReconnect(tok) {
    if (!this.reconnectToken || typeof tok !== 'string') return false;
    const want = Buffer.from(this.reconnectToken);
    const got = Buffer.from(tok);
    if (want.length !== got.length) return false;
    return timingSafeEqual(want, got);
  }

  async _verify(challengeB64, proofB64) {
    if (typeof proofB64 !== 'string') return false;
    let expected, got;
    try {
      expected = await c.sign(this.keys.macKey, c.fromB64u(challengeB64));
      got = Buffer.from(c.fromB64u(proofB64));
    } catch { return false; }
    if (expected.length !== got.length) return false;
    return timingSafeEqual(expected, got);
  }

  // ---- engine I/O ----
  sendText(str) { if (this.active) this.active.send(str); }

  // Resolves once it's OK to send more: immediately if the socket took it,
  // otherwise on 'drain' (or when the connection dies — the engine pauses then).
  sendBinary(u8) {
    const conn = this.active;
    if (!conn) return Promise.resolve(false);
    if (conn.sendBinary(Buffer.from(u8.buffer, u8.byteOffset, u8.length))) return Promise.resolve(true);
    return new Promise((resolve) => this.once('drain', () => resolve(this.active === conn)));
  }

  // Key-change / tamper: flip the client to red, tell the operator, then burn.
  _tamper(reason) {
    if (this.tampered || this.destroyed) return;
    this.tampered = true;
    try { if (this.active) this.active.send(JSON.stringify({ t: 'tamper' })); } catch {}
    this.emit('tamper', reason);
    this.emit('selfdestruct', 'KEYS CHANGED — ' + reason);
  }

  hasClient() { return !!this.active; }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.graceTimer) { clearTimeout(this.graceTimer); this.graceTimer = null; }
    const bye = (conn) => { try { conn.send(JSON.stringify({ t: 'destroyed' })); conn.close(4008, 'link destroyed'); } catch {} };
    if (this.active) bye(this.active);
    this.pending.forEach(bye);
    this.pending.clear();
    this.active = null;
    try { this.server.close(); } catch {}
  }
}

module.exports = { Relay };
