'use strict';
// Shared crypto for the operator (Node) side. The browser client mirrors this
// exactly in public/index.html so both endpoints derive identical keys.
//
// One secret — a random 32-byte session key — is carried in the URL FRAGMENT
// (`#k=...`). Browsers never send a fragment to the server, so the relay only
// ever sees /r/<token>: it cannot derive the keys or read a single message.
//
// HKDF(secret, salt) -> 64 bytes -> [0:32]=AES-GCM key, [32:64]=HMAC key.
//   * AES-GCM key encrypts every message (true e2e; only the two endpoints hold it).
//   * HMAC key answers a random challenge, so the key itself never crosses the wire.
//
// HKDF (not PBKDF2) is correct here: the secret is already full-entropy random,
// so there is nothing to stretch — and it derives instantly, which is what lets
// the target land straight in the chat instead of watching a spinner.

const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

const te = new TextEncoder();
const td = new TextDecoder();

const SECRET_BYTES = 32;                 // session key size
const HKDF_INFO = 'transfer-session-v1'; // keep in sync with public/index.html (never reuse another tool's keys)

function randomBytes(n) {
  const b = new Uint8Array(n);
  webcrypto.getRandomValues(b);
  return b;
}
function toB64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
function fromB64u(s) {
  return new Uint8Array(Buffer.from(String(s), 'base64url'));
}
function randomB64u(n) {
  return toB64u(randomBytes(n));
}

// A fresh link secret. This is the ONLY thing that unlocks the conversation.
function newSessionKey() {
  return randomB64u(SECRET_BYTES);
}

async function deriveKeys(secretB64u, saltB64u) {
  const secret = fromB64u(secretB64u);
  const salt = fromB64u(saltB64u);
  const base = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(HKDF_INFO) }, base, 512)
  );
  const encKey = await subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const macKey = await subtle.importKey('raw', bits.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return { encKey, macKey };
}

async function sign(macKey, bytes) {
  return Buffer.from(new Uint8Array(await subtle.sign('HMAC', macKey, bytes)));
}

// Short human-comparable fingerprint of the shared key (a "safety code").
// Both endpoints derive the same value; comparing it out-of-band confirms the
// channel is genuinely end-to-end with no one in the middle. Mirrored in the browser.
async function safetyCode(macKey) {
  const mac = await sign(macKey, te.encode('transfer-safety-v1'));
  const hex = mac.slice(0, 4).toString('hex').toUpperCase();
  return hex.slice(0, 4) + '-' + hex.slice(4, 8);
}

async function encrypt(encKey, text) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, encKey, te.encode(text)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toB64u(out);
}

async function decrypt(encKey, dataB64u) {
  const raw = fromB64u(dataB64u);
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, encKey, ct);
  return td.decode(pt);
}

module.exports = { randomBytes, toB64u, fromB64u, randomB64u, newSessionKey, deriveKeys, sign, safetyCode, encrypt, decrypt, SECRET_BYTES, HKDF_INFO };
