# ftproxy

Send a file to one person, privately, straight from your computer. You run
ftproxy, it gives you a link, the other person taps it on their phone or
computer, and you can swap photos, videos, PDFs and text files both ways.
Everything is encrypted end to end. When you quit, the link dies.

- **Who it's for:** anyone who wants to hand a file to one person without
  uploading it to a cloud service, making an account, or installing an app on
  their phone.
- **The other person needs nothing** but a web browser. No app, no account.
- **What it is not:** a file-sharing website, a group chat, or a way to send
  something to many people. One link, one person, one session.
- **Allowed files:** `.txt` `.png` `.jpg` `.mp4` `.pdf`, up to **500 MiB** each.
- **Status:** early version (v0.1). It has not had an independent security
  audit. Read [Residual risks](#residual-risks-read-these) before trusting it
  with something serious.

---

## Contents

1. [What you need](#what-you-need)
2. [Install (one time)](#install-one-time), or [on an Android phone](#install-on-android-termux)
3. [Use it (every time)](#use-it-every-time)
4. [If something goes wrong](#if-something-goes-wrong)
5. [Update or remove](#update-or-remove)
6. [What gets installed](#what-gets-installed)
7. [How it protects a file](#how-it-protects-a-file)
8. [Residual risks](#residual-risks-read-these)
9. [For developers](#for-developers)

---

## What you need

- A computer running **Linux** (Ubuntu, Linux Mint, Debian, Fedora, Pop!_OS and
  similar), **or** an **Android phone** with the free Termux app
  ([see the Android steps](#install-on-android-termux)).
  macOS, iPhone and Windows are not supported.
- An internet connection.
- About **250 MB** of free disk space.
- About **5 minutes** for the first install.

You do **not** need to know how to program, and you do **not** need to install
Node.js, Caddy or Cloudflare yourself. The installer handles all of that.

---

## Install (one time)

You'll type (or paste) a few lines into a program called the **Terminal**.
Take it one step at a time.

### Step 1: Open the Terminal

- **Ubuntu, Mint, Pop!_OS, Debian:** press **Ctrl + Alt + T** together.
  If nothing happens, open your apps menu, type `terminal`, and click it.
- **Fedora:** open Activities, type `terminal`, and click it.

A window with a blinking cursor opens. That's it. You're in.

> **Pasting tip:** in the Terminal, paste with **Ctrl + Shift + V** (not just
> Ctrl + V). After pasting, press **Enter** to run it.

### Step 2: Install git (the tool that downloads ftproxy)

Copy the line for your system, paste it into the Terminal, and press Enter.

| Your system | Paste this |
|---|---|
| Ubuntu, Mint, Pop!_OS, Debian | `sudo apt update && sudo apt install -y git` |
| Fedora | `sudo dnf install -y git` |

It will ask for **your computer's password**, the one you use to log in.
**When you type it, nothing appears on screen, not even dots.** That's normal.
Type it anyway and press Enter.

When the line with your name and a `$` comes back, that step is done.
If it says git is already installed, that's fine too.

### Step 3: Download and set up ftproxy

Paste this whole block and press Enter:

```bash
git clone https://github.com/Gypsy-82/ftproxy.git ~/ftproxy
cd ~/ftproxy
./install.sh
```

It downloads three helper programs (about 115 MB), checks each one against a
known fingerprint, and then tests itself. **Do not** put `sudo` in front of
it; it doesn't need it and will refuse.

When it's finished, you'll see this at the bottom:

```
  ftproxy - doctor   platform: linux

    ok node 24.22.1
    ok caddy
    ok cloudflared

  Setup finished. Start ftproxy with:

      ./ftproxy --qr
```

Three `ok` lines means you're done installing. You never have to do Steps 1-3
again on this computer.

**Shortcut for Ubuntu, Mint and Debian:** Steps 2 and 3 as one paste:

```bash
sudo apt update && sudo apt install -y git && git clone https://github.com/Gypsy-82/ftproxy.git ~/ftproxy && cd ~/ftproxy && ./install.sh
```

### Install on Android (Termux)

You can run ftproxy from your phone. The person you send to still only needs
a browser.

> Android support is new. The installer has been tested in simulation, but not
> yet on a real phone. If something here doesn't match what you see, please
> open an issue.

1. **Install Termux from F-Droid**, not the Play Store (the Play Store version
   is outdated). On your phone, open
   [f-droid.org/packages/com.termux](https://f-droid.org/packages/com.termux/),
   tap **Download APK**, open the file, and allow your browser to install apps
   when Android asks.
2. **Open Termux.** You get a black screen with a blinking cursor.
3. **Paste this whole line** (long-press the screen, tap **Paste**), then tap
   the Enter key on the keyboard:

   ```bash
   pkg update -y && pkg install -y git && git clone https://github.com/Gypsy-82/ftproxy.git ~/ftproxy && cd ~/ftproxy && ./install.sh
   ```

   If it stops and asks a question about a configuration file, just tap Enter.
4. When you see **three `ok` lines** and `Setup finished`, you're done.

To start it later, open Termux and paste `cd ~/ftproxy && ./ftproxy`.

**Things that work differently on a phone:**

- **Sending a file:** there's no picker window. First run
  `termux-setup-storage` once and tap **Allow**. Then send a file from your
  phone's Downloads folder by name, for example
  `/send ~/storage/downloads/photo.jpg`.
- **Received files** land in Termux's private folder (`~/Downloads/ftproxy-inbox`),
  where your Gallery and Files apps can't see them. To copy them to your
  phone's Downloads folder, quit ftproxy and run
  `cp ~/Downloads/ftproxy-inbox/* ~/storage/downloads/`.
- **The QR code** usually needs a wider screen than a phone has. Copy the
  link instead: long-press it, select it, and paste it into your message.

---

## Use it (every time)

### 1. Start ftproxy

Open the Terminal (Ctrl + Alt + T) and paste:

```bash
cd ~/ftproxy && ./ftproxy --qr
```

After a few seconds you'll see:

- a **link** (a long `https://...trycloudflare.com/...` address),
- a **QR code** (a square of blocks),
- a **safety code** like `F0AF-1F49`.

The link is also copied for you, so you can paste it straight into a message.

> If the QR code doesn't appear, make the Terminal window wider (or maximize
> it) and type `/qr` then Enter.

### 2. Give the link to ONE person

Either:

- they **point their phone camera at the QR code** on your screen and tap the
  link that pops up, **or**
- you **paste the link** into a private message to them (Signal, a text, etc.).

**The link is the key.** Anyone who has it can connect, so send it to one
person, once, and don't post it anywhere. Whoever opens it first gets the seat.

### 3. Check the safety code

When they connect, their screen shows a safety code too. **Read yours out to
them over the phone (or in person) and make sure it matches.** If it doesn't
match, type `/quit` right away.

### 4. Send a file to them

Type `/send` and press Enter. A window opens so you can pick the file.
(You can also drag a file from your file manager into the Terminal window and
press Enter.) Their phone asks them to accept it.

### 5. Get a file from them

They tap **Send** on their screen and choose a file. ftproxy asks you
whether to take it. Type `/accept` (or `/decline`) and press Enter.

Files you receive go to the **`ftproxy-inbox`** folder inside your
**Downloads** folder. ftproxy never opens them for you.

### 6. Finish

Type `/quit` and press Enter (or press **Ctrl + C**). The link is destroyed
and can never be used again. If the other person closes their page, the
session also ends on its own.

### All commands

Type these into ftproxy while it's running, then press Enter.

| Command | What it does |
|---|---|
| `/send` | pick a file to send (or `/send /path/to/file`) |
| `/accept` | take the file they offered |
| `/decline` | refuse the file they offered |
| `/cancel` | stop the transfer in progress |
| `/files` | list what's been sent and received |
| `/qr` | show the QR code again |
| `/safety` | show the safety code again |
| `/help` | show this list |
| `/quit` | end the session and destroy the link |

Options for starting it (`./ftproxy --help` shows all of them):

| Start with | What it does |
|---|---|
| `./ftproxy` | normal start, no QR code |
| `./ftproxy --qr` | also shows the QR code |
| `./ftproxy --inbox ~/Desktop/received` | save incoming files somewhere else |
| `./ftproxy --ttl 30` | link self-destructs after 30 minutes (default 90) |
| `./ftproxy --doctor` | check that everything is installed |

---

## If something goes wrong

**First, run the checkup.** It tells you what's missing:

```bash
cd ~/ftproxy && ./ftproxy --doctor
```

Anything marked `XX` instead of `ok` can be fixed by running `./install.sh`
again.

| You see | What to do |
|---|---|
| `git: command not found` | Do [Step 2](#step-2-install-git-the-tool-that-downloads-ftproxy) first. |
| `cd: /home/.../ftproxy: No such file or directory` | ftproxy isn't downloaded yet, or it's in a different folder. Do [Step 3](#step-3-download-and-set-up-ftproxy). |
| `Permission denied` when running `./install.sh` or `./ftproxy` | Run `bash install.sh` instead, or `sh ftproxy`. |
| `Don't run this with sudo` | Run it again without `sudo` in front. |
| `Download failed` | Check your internet connection and run `./install.sh` again. |
| `did NOT match its checksum` / `CHECKSUM MISMATCH` | The download was broken or tampered with, so nothing was installed. Wait a bit and run `./install.sh` again. If it keeps happening, open an issue on GitHub. |
| `Your Node.js is v18... too old` | Nothing to do. That's a message, not an error. Setup downloads its own copy and leaves yours alone. |
| No window opens after `/send` | Drag the file into the Terminal and press Enter, or type `/send` followed by the file's path. To get the picker window on Ubuntu: `sudo apt install -y zenity`. |
| `link copied` doesn't appear | Copying to the clipboard is optional. Select the link with your mouse and copy it with **Ctrl + Shift + C**. To enable auto-copy on Ubuntu: `sudo apt install -y xclip`. |
| `the QR code needs ... columns` | Make the Terminal window wider (or maximize it), then type `/qr`. |
| `Starting Cloudflare quick tunnel...` hangs or fails | Your network may be blocking Cloudflare. Try another network (for example your phone's hotspot). |
| Their page says the link is dead | Links die when you quit, after the time limit, or after too many wrong attempts. Start ftproxy again to get a new link. |

---

## Update or remove

**Update to the newest version:**

```bash
cd ~/ftproxy && git pull && ./install.sh
```

**Remove ftproxy completely:**

```bash
rm -rf ~/ftproxy
```

That's everything. ftproxy doesn't install anything anywhere else on your
computer. Files you received stay in `~/Downloads/ftproxy-inbox` until you
delete them yourself.

---

## What gets installed

Everything goes into the `vendor` folder inside `~/ftproxy`. Nothing is
installed system-wide, and nothing needs `sudo`.

| Program | Version | Why it's needed | Downloaded from |
|---|---|---|---|
| Node.js | 24.22.1 | runs ftproxy | nodejs.org (skipped if you already have Node 20 or newer) |
| Caddy | 2.11.7 | the local web server the link talks to | github.com/caddyserver/caddy |
| cloudflared | 2026.10.0 | the Cloudflare tunnel that makes your link reachable | github.com/cloudflare/cloudflared |

**Every download is pinned and verified.** The exact version and its SHA-256
fingerprint are written in `install.sh` (Node) and `scripts/fetch-deps.js`
(Caddy, cloudflared). If a download doesn't match its fingerprint byte for
byte, setup refuses to install it.

Tools the installer expects to already be on your computer (they are on
practically every Linux system): `bash`, `tar`, `curl` **or**
`wget`, and `sha256sum`.

Optional extras, nice to have but not required:

| Extra | Gives you | Install on Ubuntu/Debian |
|---|---|---|
| `zenity` (or `kdialog` on KDE) | the file-picker window for `/send` | `sudo apt install -y zenity` |
| `xclip`, `xsel` or `wl-copy` | link copied to clipboard automatically | `sudo apt install -y xclip` |

**On Android (Termux)** nothing goes into `vendor`. The installer runs
`pkg install nodejs caddy cloudflared` (only the ones you're missing), and
Termux's package manager checks each package's signature itself.

The ftproxy code itself has zero third-party dependencies: only Node's
built-in modules on your side and the browser's built-in WebCrypto on theirs.

---

## How it protects a file

| Threat | Control |
|---|---|
| Cloudflare / the network reads files | AES-256-GCM end to end. The key lives only in the link `#fragment`, which browsers never send. |
| Someone else uses the link | One seat, HMAC challenge auth, one-time reconnect ticket, tripwire (default 3 strikes). |
| Chunk tampered, dropped, replayed, reordered, truncated, spliced | STREAM construction: per-file HKDF key, counter nonce, `fileId ‖ index ‖ isLast` authenticated as AAD. The receiver demands exactly the next index. Plus a whole-file SHA-256. |
| Control message replayed or **reflected** back at its sender | Every envelope's AAD binds direction, the connection (server challenge ‖ guest nonce), and a strict sequence number. |
| Injected script in the guest page | CSP pins the one inline script and style by `sha256` (no `'unsafe-inline'`). `connect-src` is limited to this exact host. Upgrades from another Origin are refused. |
| Sender lies about type or size | The receiver validates magic bytes over the decrypted stream (txt across every chunk). The saved extension comes from the verified type. Size is enforced at the offer and again in the stream. |
| Path traversal, RLO, ANSI escapes in names | Basename only, NFC, controls and format chars stripped, allowlisted characters, 100-byte cap, reserved names and leading `-` neutralized. Terminal output goes through `sanitize()`. |
| Symlink / overwrite attacks on the host | Inbox must be ours and 0700. Writes use `O_EXCL\|O_NOFOLLOW` at 0600. Final names are reserved with `O_EXCL` and then renamed. `/send` refuses symlinks and re-checks dev/inode after open. |
| GPS in photos | Lossless JPEG strip, on by default: Exif/XMP/IPTC/comments, **and the MPF secondary images phones append after EOI**. |
| Disk / memory exhaustion | 500 MiB cap, a `statfs` check before accept, one transfer per direction, 1 MiB in flight. |
| Tampered helper download | Pinned versions, SHA-256 checked before anything is unpacked or made executable. |

**Fail closed.** Anything the network could have done (a GCM failure, a frame
out of order or replayed, a chunk for an unknown or finished file) is
**tamper**. Both sides turn red, partials are deleted, and the link burns. A
dishonest *peer* (wrong type, size, or hash) fails that transfer, deletes the
partial, and counts a strike.

**The QR code.** The code *is* the link, key included, so the same rules
apply: anyone who can see your screen (over your shoulder, a screen share, a
recording) can take the seat. Scan with the phone's built-in camera;
third-party scanner apps can log or upload what they read. The encoder is
in-house (`src/qr.js`), so the key never touches a library or the disk.

### What the guest page runs

The browser does not get a hand-copied "mirror" of the protocol.
`src/shared/*.js` is inlined verbatim into the page at startup (`src/page.js`),
so the browser runs the exact bytes the test suite exercises.
`test/browser.test.js` drives that page in real headless Chromium. Full design:
[DESIGN.md](DESIGN.md).

---

## Residual risks (read these)

1. **Web-delivered JS.** The guest's code is served through Cloudflare's TLS
   edge. A malicious edge could serve a modified page that leaks `#k=`, and the
   safety code can't catch that, because a tampered page can show the right
   code. The CSP hash does not help here either, since the edge can rewrite the
   header too. The fix is the planned CLI-to-CLI mode (v2).
2. **Size and timing leak.** The network sees roughly the file size (chunk
   count) and timing. Padding is planned for v2.
3. **First tap wins.** Whoever opens the link first gets the seat. Send it
   privately, once, and compare safety codes out of band.
4. **Valid is not safe.** A real PDF or MP4 can still exploit a vulnerable
   viewer. ftproxy proves the *type*, not the *intent*. Open received files in
   an up-to-date or sandboxed viewer.
5. **Dropped messages.** The edge can't forge or replay a message, but it can
   drop one or end the session. A dropped chunk is detected (tamper); a dropped
   chat line is not.
6. **Trust in the helper publishers.** The fingerprints prove you got the same
   Caddy, cloudflared and Node files that their publishers released. They
   can't protect you if a publisher's own release was compromised.
7. **Not audited.**

---

## For developers

The test suite needs one dev-only package (`ws`, used to play a hostile
client). Node 22 or newer is needed to run the tests (the app itself runs on
20+). If you used the installer's private Node, put it first on your `PATH`:

```bash
export PATH="$PWD/vendor/node/bin:$PATH"   # only if ./install.sh downloaded Node
npm install
npm test     # 82 tests: crypto KATs vs OpenSSL, every §15 negative case, hostile-edge
             # protocol tests, full stack incl. a 500 MiB transfer, QR spec KATs + read-back,
             # and the real page in headless Chromium (skipped if none is found; CHROME=/path to pick one)
```

`test/vectors.json` is generated independently from the spec with OpenSSL by
`node scripts/make-vectors.js`.

Not yet verified: a real 500 MiB transfer **through a Cloudflare quick tunnel**
(DESIGN.md §15).

## License

MIT, see [LICENSE](LICENSE). ftproxy is a fork of SMSproxy.
