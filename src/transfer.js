'use strict';
// Host binding for the shared transfer engine: wires the Relay (wire), the
// Inbox (where guest files land) and hostfile (what /send reads) into one
// Engine, and routes its verdicts back to the relay:
//   tamper -> relay._tamper (red on both sides, link burns)
//   strike -> relay.strike  (bad transfer counts toward the tripwire)
const { Engine } = require('./shared/engine');
const sc = require('./shared/stream-crypto');
const { openHostSource, nodeHasher } = require('./hostfile');

function createHostEngine({ relay, secret, encKey, inbox, offerTtlMs, resumeWaitMs }) {
  return sc.importSecret(secret).then((base) => {
    const engine = new Engine({
      role: 'host', base, encKey, offerTtlMs, resumeWaitMs,
      hashFactory: nodeHasher,
      io: { sendText: (s) => relay.sendText(s), sendBinary: (u8) => relay.sendBinary(u8) },
      canAccept: async (view) => inbox.checkSpace(view.size),
      openSink: async (view) => inbox.open(view),
    });
    relay.on('client-online', (bind) => engine.connect(bind));
    relay.on('client-offline', () => engine.disconnect());
    relay.on('envelope', (m) => engine.onText(m));
    relay.on('binary', (u8) => engine.onBinary(u8));
    engine.on('tamper', (why) => relay._tamper(why));
    engine.on('strike', (why) => relay.strike(why));
    return engine;
  });
}

// /send <path>: build the source (hash, type, EXIF strip), then offer it.
async function sendPath(engine, p, opts) {
  const src = await openHostSource(p, opts);
  try {
    const view = await engine.offer(src);
    return { view, warn: src.warn, path: src.path };
  } catch (e) {
    src.close();
    throw e;
  }
}

module.exports = { createHostEngine, sendPath };
