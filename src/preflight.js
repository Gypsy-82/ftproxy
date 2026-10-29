'use strict';
// Dependency checks + platform-aware install hints. Powers `--doctor` and the
// preflight the launcher runs for the chosen reach mode.
const { spawnSync } = require('child_process');
const vendor = require('./vendor');

const isTermux = !!(process.env.PREFIX && process.env.PREFIX.includes('com.termux'));

function has(cmd, args) {
  try {
    const r = spawnSync(cmd, args, { stdio: 'ignore', timeout: 4000 });
    return !r.error && r.status === 0;
  } catch { return false; }
}

function manual(tool) {
  if (tool === 'caddy') {
    if (isTermux) return 'pkg install caddy';
    return 'https://caddyserver.com/download';
  }
  if (isTermux) return 'pkg install cloudflared';
  return 'https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/';
}

function hint(tool) {
  return `run ./install.sh to fetch it automatically  (or: ${manual(tool)})`;
}

function check() {
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
  return {
    node: { ok: nodeMajor >= 20, version: process.versions.node, need: '>= 20' },
    caddy: { ok: has(vendor.resolve('caddy'), ['version']), hint: hint('caddy') },
    cloudflared: { ok: has(vendor.resolve('cloudflared'), ['--version']), hint: hint('cloudflared') },
    platform: isTermux ? 'android (termux)' : process.platform,
  };
}

module.exports = { check, hint, has, isTermux };
