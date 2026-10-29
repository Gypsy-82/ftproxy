#!/usr/bin/env bash
# One-time setup. Run it from inside the ftproxy folder:   ./install.sh
#
# Linux and Android (Termux) only.
#
# What it does on Linux, and nothing else:
#   1. Uses your Node.js if it is version 20 or newer. If not, it downloads the
#      official Node.js build into ./vendor/node (this folder only; nothing is
#      installed system-wide, no sudo).
#   2. Downloads caddy and cloudflared into ./vendor (scripts/fetch-deps.js).
#   3. Runs the built-in doctor to confirm everything works.
# Every download is a pinned version checked against a SHA-256 written in this
# repo. If a file does not match, setup stops and installs nothing.
# To undo it all: delete the ./vendor folder.
#
# On Android (Termux) it installs nodejs, caddy and cloudflared with Termux's
# own package manager (pkg), which checks the packages' signatures itself.
set -euo pipefail
cd "$(dirname "$0")"

NODE_V="24.22.1"
NODE_MIN=20

say()  { printf '  %s\n' "$*"; }
fail() { printf '\n  x %s\n\n' "$*" >&2; exit 1; }

echo
echo "ftproxy setup"
echo

# Running as root would leave root-owned files in your folder.
if [ "$(id -u)" -eq 0 ] && [ -z "${PREFIX:-}" ]; then
  fail "Don't run this with sudo. Run it as yourself:   ./install.sh"
fi

[ "$(uname -s)" = Linux ] || fail "Unsupported system: $(uname -s). ftproxy runs on Linux and Android (Termux) only."

node_major() { "$1" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }

# ---- Android (Termux) -------------------------------------------------------
# The desktop builds don't run on Android, so everything comes from pkg.
if [ -n "${PREFIX:-}" ] && [[ "$PREFIX" == *com.termux* ]]; then
  say "Android (Termux) detected. Installing what's missing with pkg..."
  NEED=""
  if ! command -v node >/dev/null 2>&1 || [ "$(node_major node)" -lt "$NODE_MIN" ]; then NEED="$NEED nodejs"; fi
  command -v caddy >/dev/null 2>&1 || NEED="$NEED caddy"
  command -v cloudflared >/dev/null 2>&1 || NEED="$NEED cloudflared"
  if [ -n "$NEED" ]; then
    # shellcheck disable=SC2086
    pkg install -y $NEED || fail "pkg could not install:$NEED
    Run  pkg update  then ./install.sh again."
  fi
  for t in node caddy cloudflared; do
    command -v "$t" >/dev/null 2>&1 || fail "$t is still missing after pkg install.
    Run  pkg update  then ./install.sh again."
  done
  [ "$(node_major node)" -ge "$NODE_MIN" ] || fail "Node.js $(node -v) is too old. Run  pkg upgrade nodejs  then ./install.sh again."
  chmod +x ftproxy bin/ftproxy.js 2>/dev/null || true
  node bin/ftproxy.js --doctor
  echo "  Setup finished. Start ftproxy with:"
  echo
  echo "      ./ftproxy"
  echo
  exit 0
fi

# ---- Linux ------------------------------------------------------------------
OS=linux
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)             fail "Unsupported processor: $(uname -m). Need x86_64 or arm64." ;;
esac

fetch() {  # fetch URL DEST
  if command -v curl >/dev/null 2>&1; then curl -fL --progress-bar --retry 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q --show-progress -O "$2" "$1"
  else fail "Need curl or wget to download. On Ubuntu/Debian run:  sudo apt install -y curl"
  fi
}
sha256() { sha256sum "$1" | cut -d' ' -f1; }

# ---- 1. Node.js -------------------------------------------------------------
if [ -x vendor/node/bin/node ] && [ "$(cat vendor/node.version 2>/dev/null)" = "$NODE_V" ]; then
  NODE=vendor/node/bin/node
  say "ok  Node $("$NODE" -v) (in ./vendor, verified)"
elif command -v node >/dev/null 2>&1 && [ "$(node_major node)" -ge "$NODE_MIN" ]; then
  NODE=node
  say "ok  Node $(node -v) (already on this computer)"
else
  if command -v node >/dev/null 2>&1; then
    say "Your Node.js is $(node -v), which is too old (need $NODE_MIN or newer)."
    say "Leaving it alone and downloading a private copy just for ftproxy."
  else
    say "Node.js not found. Downloading a private copy just for ftproxy."
  fi
  case "$OS-$ARCH" in
    linux-x64)    WANT=eb6728e77c576a35162c122c45ccadf224d89ff00abc8dae46cc2897c6002d7c ;;
    linux-arm64)  WANT=33c37be234ba8bee041961047b19160f4d7d0f164e8e246f78bdd10feff148b3 ;;
  esac
  NAME="node-v$NODE_V-$OS-$ARCH"
  mkdir -p vendor
  TGZ="vendor/$NAME.tar.gz.part"
  trap 'rm -rf "$TGZ" vendor/.node-x' EXIT
  fetch "https://nodejs.org/dist/v$NODE_V/$NAME.tar.gz" "$TGZ" \
    || fail "Download failed. Check your internet connection and run ./install.sh again."
  GOT="$(sha256 "$TGZ")"
  if [ "$GOT" != "$WANT" ]; then
    fail "Node.js download did NOT match its checksum. Nothing was installed.
  expected $WANT
  got      $GOT
  This can mean a broken download or a tampered file. Try again later."
  fi
  rm -rf vendor/.node-x vendor/node
  mkdir vendor/.node-x
  tar -xzf "$TGZ" -C vendor/.node-x || fail "Could not unpack Node.js (is tar installed?)"
  mv "vendor/.node-x/$NAME" vendor/node
  echo "$NODE_V" > vendor/node.version
  NODE=vendor/node/bin/node
  say "ok  Node $("$NODE" -v) (downloaded to ./vendor, checksum verified)"
fi

chmod +x ftproxy bin/ftproxy.js 2>/dev/null || true

# ---- 2. caddy + cloudflared -------------------------------------------------
if ! "$NODE" scripts/fetch-deps.js; then
  fail "Could not get caddy/cloudflared (see the message above).
    Check your internet connection, then run ./install.sh again."
fi

# ---- 3. check -------------------------------------------------------------
"$NODE" bin/ftproxy.js --doctor

echo "  Setup finished. Start ftproxy with:"
echo
echo "      ./ftproxy --qr"
echo
