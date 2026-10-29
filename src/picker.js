'use strict';
// Native file picker for a bare "/send". It only CHOOSES a path: whatever it
// returns goes through sendPath's checks (no symlinks/dirs/devices, type from
// the bytes) exactly like a typed path. Spawned with fixed args and no shell;
// nothing that came from the guest is ever passed to it.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const TITLE = 'ftproxy - choose a file to send';
const GLOBS = ['txt', 'png', 'jpg', 'jpeg', 'mp4', 'pdf'].flatMap((e) => ['*.' + e, '*.' + e.toUpperCase()]).join(' ');
const MAX_OUT = 8192;                         // a path, not a novel

function onPath(cmd, env) {
  return (env.PATH || '').split(path.delimiter).some((d) => {
    try { fs.accessSync(path.join(d, cmd), fs.constants.X_OK); return true; } catch { return false; }
  });
}

// zenity (GNOME and most others), then kdialog (KDE). No display -> none
// (e.g. over SSH): the caller falls back to the usage line.
function findPicker(env = process.env, has = (c) => onPath(c, env)) {
  if (!env.DISPLAY && !env.WAYLAND_DISPLAY) return null;
  const home = os.homedir() + '/';
  if (has('zenity')) return { cmd: 'zenity', args: ['--file-selection', '--title=' + TITLE, '--filename=' + home, '--file-filter=Allowed files | ' + GLOBS] };
  if (has('kdialog')) return { cmd: 'kdialog', args: ['--title', TITLE, '--getopenfilename', home, GLOBS + '|Allowed files'] };
  return null;
}

// Resolves to an absolute path, or null if cancelled / failed / odd output.
// Returns { promise, kill } so a self-destruct can close an open dialog.
function pickFile(picker) {
  let child;
  const promise = new Promise((resolve) => {
    let out = '', over = false;
    try { child = spawn(picker.cmd, picker.args, { stdio: ['ignore', 'pipe', 'ignore'], shell: false }); } catch { resolve(null); return; }
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d) => { out += d; if (out.length > MAX_OUT) { over = true; try { child.kill(); } catch {} } });
    child.on('error', () => resolve(null));
    child.on('close', (code) => {
      const p = out.replace(/\n$/, '');      // strip only the terminator; a name may contain anything else
      resolve(code === 0 && !over && p && !p.includes('\0') && path.isAbsolute(p) ? p : null);
    });
  });
  return { promise, kill: () => { if (child && child.exitCode === null) { try { child.kill(); } catch {} } } };
}

module.exports = { findPicker, pickFile, GLOBS };
