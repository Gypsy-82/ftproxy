'use strict';
// Builds the guest page once at startup.
//
// SMSproxy hand-mirrored its crypto into index.html, which means two copies
// that can silently drift. Here the browser's protocol code is not a mirror at
// all: src/shared/*.js is inlined VERBATIM at the /*@@SHARED@@*/ marker, so the
// bytes the guest runs are the bytes test/ exercises in Node.
//
// It also hashes the final inline <script> and <style> so the CSP can name
// them exactly ('sha256-…') instead of allowing 'unsafe-inline' — an injected
// script tag, even one smuggled in through a future bug, will not execute.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const INDEX = path.join(__dirname, '..', 'public', 'index.html');
const SHARED_DIR = path.join(__dirname, 'shared');
// Dependency order: each module may only require ones above it.
const SHARED_ORDER = ['sha256', 'stream-crypto', 'filetype', 'names', 'exif', 'engine'];
const MARKER = '/*@@SHARED@@*/';

function only(html, tag) {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g');
  const all = [...html.matchAll(re)];
  if (all.length !== 1) throw new Error(`page must contain exactly one <${tag}> block (found ${all.length})`);
  return all[0][1];
}
const cspHash = (s) => `'sha256-${crypto.createHash('sha256').update(s, 'utf8').digest('base64')}'`;

function sharedSource() {
  return SHARED_ORDER.map((n) => {
    const src = fs.readFileSync(path.join(SHARED_DIR, n + '.js'), 'utf8');
    if (/<\/script|<!--/i.test(src)) throw new Error(`shared/${n}.js contains a sequence that would break out of <script>`);
    return `// ---- src/shared/${n}.js ----\n${src}`;
  }).join('\n');
}

function buildPage(indexPath = INDEX) {
  const tpl = fs.readFileSync(indexPath, 'utf8');
  if (tpl.split(MARKER).length !== 2) throw new Error('index.html must contain the shared-code marker exactly once');
  const html = tpl.replace(MARKER, () => sharedSource());
  return {
    html: Buffer.from(html, 'utf8'),
    scriptHash: cspHash(only(html, 'script')),
    styleHash: cspHash(only(html, 'style')),
  };
}

module.exports = { buildPage, SHARED_ORDER, MARKER };
