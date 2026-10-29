// Transfer engine: the per-session state machine of DESIGN.md §5, shared by
// both endpoints. The host (src/transfer.js) and the guest page run THIS code;
// only the I/O adapters differ (fd vs File.slice, inbox vs Blob).
//
// Concurrency model: every inbound frame AND every local action goes through
// one serial promise queue, so no two handlers ever interleave across an
// await. The only thing outside the queue is the sender's pump, which re-checks
// state after every await.
//
// Failure classes (§4.6):
//   tamper  — anything the network could have done: a frame that fails GCM, a
//             replayed/reordered envelope, a chunk out of order or for an
//             unknown file. Everything stops, partials are deleted, link burns.
//   failed  — the authenticated PEER misbehaved: wrong type, wrong size, hash
//             mismatch. That transfer dies (partial deleted), the session lives,
//             and it counts as a 'strike' toward the tripwire.
//
// io = { sendText(str), sendBinary(u8) -> Promise<boolean> }   // resolves once
//      it's OK to send more (backpressure), false if the connection is gone
//
// ISOMORPHIC: runs in Node and is inlined verbatim into the guest page.
(function (name, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require);
  else { const TX = (globalThis.TX = globalThis.TX || {}); TX[name] = factory((d) => TX[d.slice(2)]); }
})('engine', function (require) {
  'use strict';

  const sc = require('./stream-crypto');
  const ft = require('./filetype');
  const names = require('./names');
  const sha = require('./sha256');

  const OFFER_TTL_MS = 120 * 1000;
  const RESUME_WAIT_MS = 15 * 1000;
  const MAX_CHAT = 4000;
  const ACTIVE = new Set(['offered', 'streaming', 'paused']);

  class Engine {
    constructor({ role, base, encKey, io, hashFactory, openSink, canAccept, offerTtlMs, resumeWaitMs }) {
      if (role !== 'host' && role !== 'guest') throw new Error('role must be host or guest');
      this.role = role;
      this.myDir = role === 'host' ? sc.DIR.H2G : sc.DIR.G2H;
      this.peerDir = role === 'host' ? sc.DIR.G2H : sc.DIR.H2G;
      this.base = base;                 // HKDF key over the link secret
      this.encKey = encKey;             // session AES-GCM key
      this.io = io;
      this.hashFactory = hashFactory || sha.create;
      this.openSink = openSink;         // async (view) -> { write(i, u8), commit() -> result, abort() }
      this.canAccept = canAccept || (async () => null);   // async (view) -> null | 'reason'
      this.offerTtlMs = offerTtlMs || OFFER_TTL_MS;
      this.resumeWaitMs = resumeWaitMs || RESUME_WAIT_MS;

      this.handlers = {};
      this.out = null;                  // my outgoing transfer (one per direction)
      this.inc = null;                  // the peer's incoming transfer
      this.history = [];                // finished transfers, for /files
      this.seen = new Set();            // every fileId offered either way: a key is never reused
      this.closedIds = new Set();       // stray in-flight chunks for these are dropped, not tamper
      this.bind = null;                 // connection binding (48 B) — null while offline
      this.txSeq = 0;
      this.rxSeq = 0;
      this.queue = Promise.resolve();
      this.txChain = Promise.resolve();
      this.dead = false;
    }

    on(ev, fn) { (this.handlers[ev] = this.handlers[ev] || []).push(fn); return this; }
    _emit(ev, ...args) { for (const fn of this.handlers[ev] || []) fn(...args); }

    _enqueue(fn) {
      const p = this.queue.then(() => (this.dead ? undefined : fn()));
      this.queue = p.catch((e) => this._emit('error', e));
      return p;
    }

    // ---------- connection lifecycle ----------
    connect(bind) {
      return this._enqueue(async () => {
        if (!(bind instanceof Uint8Array) || bind.length !== sc.BIND_BYTES) throw new Error('bad binding');
        this.bind = bind;
        this.txSeq = 0;
        this.rxSeq = 0;
        this.txChain = Promise.resolve();
        const o = this.out, n = this.inc;
        // A pending offer is re-sent: a peer that reloaded has forgotten it, a peer
        // that didn't just ignores the duplicate (same id, still 'offered').
        if (o && o.state === 'offered') await this._send(this._offerMsg(o));
        if (o && o.state === 'paused') {
          clearTimeout(o.resumeTimer);
          o.resumeTimer = setTimeout(() => this._enqueue(() => {
            if (this.out === o && o.state === 'paused') this._fail(o, 'peer did not resume in time', { notify: true });
          }), this.resumeWaitMs);
        }
        if (n && n.state === 'paused') {
          n.state = 'streaming';
          this._emit('state', this._view(n));
          await this._send({ op: 'accept', id: n.id, from: n.next });
        }
      });
    }

    disconnect() {
      return this._enqueue(() => {
        this.bind = null;
        for (const t of [this.out, this.inc]) {
          if (t && t.state === 'streaming') { t.state = 'paused'; this._emit('state', this._view(t)); }
        }
      });
    }

    destroy() {
      if (this.dead) return;
      this.dead = true;
      for (const t of [this.out, this.inc]) if (t) this._dispose(t);
    }

    // ---------- inbound from the wire ----------
    onText(m) {
      const bind = this.bind;
      return this._enqueue(() => (bind && bind === this.bind ? this._rxEnv(m) : undefined));
    }
    onBinary(u8) {
      const bind = this.bind;
      return this._enqueue(() => (bind && bind === this.bind ? this._rxChunk(u8) : undefined));
    }

    async _rxEnv(m) {
      if (!m || m.t !== 'x' || m.s !== this.rxSeq + 1 || typeof m.d !== 'string') {
        return this._tamper('a control message was replayed, reordered or dropped');
      }
      let o;
      try { o = await sc.openEnv(this.encKey, this.peerDir, this.bind, m.s, m.d); }
      catch { return this._tamper('a control message failed key authentication'); }
      this.rxSeq = m.s;
      switch (o.op) {
        case 'msg': return this._onChat(o);
        case 'offer': return this._onOffer(o);
        case 'accept': return this._onAccept(o);
        case 'decline': return this._onDecline(o);
        case 'ack': return this._onAck(o);
        case 'done': return this._onDone(o);
        case 'cancel': return this._onCancel(o);
        default: return this._strike('unknown control op');
      }
    }

    async _rxChunk(frame) {
      const h = sc.parseHeader(frame);
      if (!h) return this._tamper('a malformed file chunk arrived');
      const id = sc.toB64u(h.fileId);
      const t = this.inc;
      if (!t || t.id !== id) {
        if (this.closedIds.has(id)) return;          // in flight when we cancelled — harmless
        return this._tamper('a chunk arrived for a transfer that does not exist');
      }
      if (t.state !== 'streaming') return this._tamper('a chunk arrived before it was accepted');
      if (h.index !== t.next) return this._tamper('a file chunk arrived out of order');
      let pt;
      try { pt = await sc.openChunk(t.key, frame, t.next); }
      catch { return this._tamper('a file chunk failed key authentication'); }

      const last = h.index === t.total - 1;
      if (h.isLast !== last) return this._fail(t, 'the stream length does not match the offer', { notify: true, strike: true });
      if (pt.length !== sc.expectedLen(t.size, h.index)) return this._fail(t, 'size does not match the offer', { notify: true, strike: true });
      try { t.validator.push(pt); }
      catch (e) { return this._fail(t, e.message, { notify: true, strike: true }); }
      t.hasher.update(pt);
      try { await t.sink.write(h.index, pt); }
      catch (e) { return this._fail(t, 'could not write: ' + (e && e.message), { notify: true }); }
      t.next += 1;
      t.bytes += pt.length;
      this._emit('progress', this._view(t));

      if (!last) {
        if (t.next % sc.ACK_EVERY === 0) await this._send({ op: 'ack', id: t.id, next: t.next });
        return;
      }
      try { t.validator.finish(); }
      catch (e) { return this._fail(t, e.message, { notify: true, strike: true }); }
      if (t.hasher.hex() !== t.sha256) return this._fail(t, 'hash mismatch — the file is not what was offered', { notify: true, strike: true });
      try { t.result = await t.sink.commit(); }
      catch (e) { return this._fail(t, 'could not save: ' + (e && e.message), { notify: true }); }
      t.sink = null;
      this._finish(t, 'done');
      await this._send({ op: 'ack', id: t.id, next: t.next });
      await this._send({ op: 'done', id: t.id, ok: true });
      this._emit('done', this._view(t), t.result);
    }

    // ---------- control ops (peer -> me) ----------
    _onChat(o) {
      if (typeof o.text !== 'string' || !o.text || o.text.length > MAX_CHAT) return this._strike('bad chat message');
      this._emit('chat', o.text);
    }

    async _onOffer(o) {
      let idBytes = null;
      try { idBytes = sc.fromB64u(o.id); } catch {}
      if (!idBytes || idBytes.length !== 16) return this._strike('offer with a bad id');
      const cleaned = typeof o.name === 'string' && o.name.length <= 1024 && ft.TYPES.includes(o.type)
        ? names.cleanName(o.name, o.type) : '';
      const valid = cleaned &&
        Number.isSafeInteger(o.size) && o.size >= 0 && o.size <= sc.MAX_SIZE &&
        typeof o.sha256 === 'string' && /^[0-9a-f]{64}$/.test(o.sha256);
      if (!valid) { this._strike('invalid offer'); return this._send({ op: 'decline', id: o.id, reason: 'invalid offer' }); }

      if (this.inc && this.inc.id === o.id && this.inc.state === 'offered') return;   // re-offer after reconnect
      if (this.seen.has(o.id)) return this._send({ op: 'decline', id: o.id, reason: 'duplicate id' });
      this.seen.add(o.id);
      if (this.inc && ACTIVE.has(this.inc.state)) return this._send({ op: 'decline', id: o.id, reason: 'busy' });

      const t = {
        dir: 'in', id: o.id, idBytes, name: cleaned, size: o.size, type: o.type, sha256: o.sha256,
        stripped: o.stripped === true, total: sc.totalChunks(o.size), state: 'offered', next: 0, bytes: 0,
      };
      t.expireTimer = setTimeout(() => this._enqueue(async () => {
        if (this.inc !== t || t.state !== 'offered') return;
        this._finish(t, 'expired');
        await this._send({ op: 'decline', id: t.id, reason: 'expired' });
      }), this.offerTtlMs);
      this.inc = t;
      this._emit('offer', this._view(t));
    }

    async _onAccept(o) {
      const t = this.out;
      if (!t || t.id !== o.id || !ACTIVE.has(t.state)) {
        if (typeof o.id === 'string' && o.id.length <= 32) await this._send({ op: 'cancel', id: o.id, reason: 'unknown transfer' });
        return;
      }
      const from = o.from;
      if (t.state === 'offered' && from === 0) {
        clearTimeout(t.expireTimer);
        t.state = 'streaming';
        t.started = Date.now();
      } else if (t.state === 'paused' && Number.isInteger(from) && from >= t.acked && from <= t.next) {
        clearTimeout(t.resumeTimer);
        t.state = 'streaming';
        t.next = from;                   // rewind to what the receiver actually holds
        t.acked = from;
      } else {
        return this._fail(t, 'peer asked for an impossible resume point', { notify: true, strike: true });
      }
      this._emit('state', this._view(t));
      this._pump(t);
    }

    _onDecline(o) {
      const t = this.out;
      if (!t || t.id !== o.id || t.state !== 'offered') return;
      this._finish(t, 'declined', typeof o.reason === 'string' ? o.reason.slice(0, 80) : '');
    }

    _onAck(o) {
      const t = this.out;
      if (!t || t.id !== o.id || t.state !== 'streaming') return;
      if (!Number.isInteger(o.next) || o.next < t.acked || o.next > t.next) return this._strike('impossible ack');
      t.acked = o.next;
      this._pump(t);
    }

    _onDone(o) {
      const t = this.out;
      if (!t || t.id !== o.id || !ACTIVE.has(t.state)) return;
      if (o.ok === true && t.next === t.total) {
        this._finish(t, 'done');
        this._emit('done', this._view(t), null);
      } else {
        this._fail(t, 'receiver rejected it: ' + (typeof o.reason === 'string' ? o.reason.slice(0, 120) : 'unknown'), {});
      }
    }

    _onCancel(o) {
      const why = 'cancelled by the other side' + (typeof o.reason === 'string' && o.reason ? ': ' + o.reason.slice(0, 120) : '');
      for (const t of [this.out, this.inc]) {
        if (t && t.id === o.id && ACTIVE.has(t.state)) this._fail(t, why, {});
      }
    }

    // ---------- local actions ----------
    chat(text) {
      return this._enqueue(() => {
        const s = String(text).slice(0, MAX_CHAT);
        return s ? this._send({ op: 'msg', text: s }) : false;
      });
    }

    // src = { name, size, type, sha256, stripped, read(i) -> Promise<Uint8Array>, close() }
    offer(src) {
      return this._enqueue(async () => {
        if (this.out && ACTIVE.has(this.out.state)) throw new Error('you already have a file on offer or sending — /cancel it first');
        if (!this.bind) throw new Error('nobody is connected');
        if (!ft.TYPES.includes(src.type) || !Number.isSafeInteger(src.size) || src.size < 0 || src.size > sc.MAX_SIZE) {
          throw new Error('file is not an allowed type/size');
        }
        let idBytes, id;
        do { idBytes = sc.randomBytes(16); id = sc.toB64u(idBytes); } while (this.seen.has(id));
        this.seen.add(id);
        const t = {
          dir: 'out', id, idBytes, name: src.name, size: src.size, type: src.type, sha256: src.sha256,
          stripped: !!src.stripped, total: sc.totalChunks(src.size), state: 'offered',
          next: 0, acked: 0, bytes: 0, src, key: await sc.fileKey(this.base, idBytes, this.myDir),
        };
        // The receiver auto-declines at its TTL; this is the backstop if that never arrives.
        t.expireTimer = setTimeout(() => this._enqueue(() => {
          if (this.out === t && t.state === 'offered') this._finish(t, 'expired');
        }), this.offerTtlMs + 5000);
        this.out = t;
        this._emit('outgoing', this._view(t));
        await this._send(this._offerMsg(t));
        return this._view(t);
      });
    }

    accept() {
      return this._enqueue(async () => {
        const t = this.inc;
        if (!t || t.state !== 'offered') return false;
        const why = await this.canAccept(this._view(t));
        if (why) {
          this._finish(t, 'declined', why);
          await this._send({ op: 'decline', id: t.id, reason: why });
          return false;
        }
        clearTimeout(t.expireTimer);
        try {
          t.key = await sc.fileKey(this.base, t.idBytes, this.peerDir);
          t.sink = await this.openSink(this._view(t));
        } catch (e) {
          this._finish(t, 'failed', 'could not open a place to save it: ' + (e && e.message));
          await this._send({ op: 'decline', id: t.id, reason: 'receiver could not save' });
          return false;
        }
        t.validator = ft.validator(t.type);
        t.hasher = this.hashFactory();
        t.state = 'streaming';
        t.started = Date.now();
        this._emit('state', this._view(t));
        await this._send({ op: 'accept', id: t.id, from: 0 });
        return true;
      });
    }

    decline() {
      return this._enqueue(async () => {
        const t = this.inc;
        if (!t || t.state !== 'offered') return false;
        this._finish(t, 'declined', 'you declined');
        await this._send({ op: 'decline', id: t.id, reason: 'declined' });
        return true;
      });
    }

    cancel() {
      return this._enqueue(() => {
        let n = 0;
        for (const t of [this.out, this.inc]) {
          if (t && ACTIVE.has(t.state)) { this._fail(t, 'cancelled', { notify: true }); n++; }
        }
        return n;
      });
    }

    // ---------- sender pump ----------
    async _pump(t) {
      if (t.pumping) return;
      t.pumping = true;
      try {
        while (this.out === t && t.state === 'streaming' && !this.dead && t.next < t.total && t.next - t.acked < sc.MAX_INFLIGHT) {
          const i = t.next;
          const pt = await t.src.read(i);
          if (pt.length !== sc.expectedLen(t.size, i)) throw new Error('file changed while sending');
          const frame = await sc.sealChunk(t.key, t.idBytes, i, i === t.total - 1, pt);
          if (this.out !== t || t.state !== 'streaming' || t.next !== i) continue;   // resumed/cancelled meanwhile
          t.next = i + 1;
          t.bytes = Math.min(t.size, t.next * sc.CHUNK);
          await this.io.sendBinary(frame);
          this._emit('progress', this._view(t));
        }
      } catch (e) {
        this._enqueue(() => {
          if (this.out === t && ACTIVE.has(t.state)) this._fail(t, (e && e.message) || 'read failed', { notify: true });
        });
      } finally {
        t.pumping = false;
      }
    }

    // ---------- endings ----------
    _finish(t, state, reason) {
      t.state = state;
      t.reason = reason || '';
      t.ended = Date.now();
      // Chunks can legitimately still be in flight after a cancel/decline/fail,
      // so those ids are dropped quietly. A COMPLETED file has no such excuse:
      // a chunk for it afterwards is a replay, and falls through to tamper.
      if (state !== 'done') this.closedIds.add(t.id);
      this._dispose(t);
      this.history.push(t);
      this._emit('state', this._view(t));
    }

    _fail(t, reason, { notify = false, strike = false } = {}) {
      if (!ACTIVE.has(t.state)) return;
      this._finish(t, 'failed', reason);
      this._emit('failed', this._view(t), reason);
      if (strike) this._emit('strike', reason);
      if (notify) this._send({ op: 'cancel', id: t.id, reason: String(reason).slice(0, 120) });
    }

    _dispose(t) {
      clearTimeout(t.expireTimer);
      clearTimeout(t.resumeTimer);
      if (t.sink) { try { t.sink.abort(); } catch {} t.sink = null; }     // partial is deleted
      if (t.src) { try { t.src.close(); } catch {} t.src = null; }
    }

    _strike(reason) { this._emit('strike', reason); }

    _tamper(reason) {
      if (this.dead) return;
      this.destroy();
      this._emit('tamper', reason);
    }

    // ---------- helpers ----------
    _offerMsg(t) {
      return { op: 'offer', id: t.id, name: t.name, size: t.size, type: t.type, sha256: t.sha256, stripped: t.stripped };
    }

    _send(obj) {
      // Serialized so seq numbers hit the wire in the order they were assigned.
      const p = this.txChain.then(async () => {
        const bind = this.bind;
        if (!bind || this.dead) return false;
        const seq = ++this.txSeq;
        const d = await sc.sealEnv(this.encKey, this.myDir, bind, seq, obj);
        if (bind !== this.bind || this.dead) return false;
        this.io.sendText(JSON.stringify({ t: 'x', s: seq, d }));
        return true;
      });
      this.txChain = p.catch(() => false);
      return p;
    }

    _view(t) {
      return {
        id: t.id, dir: t.dir, name: t.name, size: t.size, type: t.type, sha256: t.sha256, stripped: t.stripped,
        state: t.state, reason: t.reason || '', bytes: t.bytes, next: t.next, total: t.total,
        started: t.started || 0, ended: t.ended || 0, result: t.result,
      };
    }

    status() {
      return {
        out: this.out ? this._view(this.out) : null,
        inc: this.inc ? this._view(this.inc) : null,
        history: this.history.map((t) => this._view(t)),
      };
    }
  }

  return { Engine, OFFER_TTL_MS, RESUME_WAIT_MS, MAX_CHAT };
});
