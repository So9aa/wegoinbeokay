# wegoinbeokay — PS5 13.60 research

A browser-side reachability lab for PS5 firmware 13.60.

This is **not** a jailbreak. There is no working PS5 kernel exploit for
13.00 – 13.60 as of 2026-09-26. What is here is a fully instrumented
userland stack, a hardware-verified ROP syscall executor for 13.60, and
the record of every kernel-reachability test that has been run against
this firmware — including the tests that came back negative.

If you want a working jailbreak today, use a console on **12.00 – 12.70**
and the upstream p2jb. This repo runs that same engine, and the deployed
site still hosts both. See "Working jailbreak" below.

---

## What this repo actually contains

Two things, cleanly separated.

**1. A working PS5 browser-side toolkit** (upstream slopkit lineage, unchanged):

- WebKit ROP primitive (`core.js`, `mem.js`, `int64.js`)
- libkernel base derivation + per-firmware offset loading (`main.js`, `offsets/*.js`)
- Synchronous ROP syscall executor (`rop-worker.js`, `p2jb_lk.js`, `p2jb_poops.js`)
- Two upstream kernel exploit chains that still work on their target firmwares:
  - **P2JB** — `cr_ref` overflow via `kqueueex`, firmware **12.00 – 12.70**
  - **Poopsploit** — IPv6 `rthdr` UAF, firmware **9.00 – 12.00**

**2. A 13.60 reachability study** (this repo's own work):

A set of probes that call every AIO / osem / socket syscall the two upstream
chains depend on, on a real 13.60 console, and record what the kernel answered. The study is the interesting artefact here — see `docs/FINDINGS.md`.

The 13.60 side does **not** reach a kernel primitive. Its purpose is to
establish, empirically and reproducibly, which primitives exist on 13.60
and which do not, so that any future 13.60 exploit can start from a known
state instead of re-measuring.

---

## Working jailbreak

The two upstream chains still work on their original firmwares and are
selectable from `index.html`.

| exploit    | firmware      | technique                              | status |
|------------|---------------|----------------------------------------|--------|
| P2JB       | 12.00 – 12.70 | `cr_ref` overflow via `kqueueex`       | works |
| Poopsploit | 9.00 – 12.00  | IPv6 `rthdr` UAF                       | works |
| Syscall test | 13.00 – 13.60 | AIO / osem / socket reachability only | research |

12.00 is the only firmware both upstream chains cover.

To jailbreak a 12.xx or 9.xx – 12.00 console: open `index.html` on the
console browser and tap the relevant entry. Same behaviour as upstream
slopkit.

The Syscall test entry on 13.xx runs the research probes and stops. It
writes no kernel memory, and cannot jailbreak the console.

---

## What was measured on 13.60 (short version)

Full record in [`docs/FINDINGS.md`](docs/FINDINGS.md).

**Working:**

- WebKit primitive completes; ROP executor `fired=183`.
- getpid / getuid / kqueue / pipe2 / socketpair-alternate (`pipe2`) all return real values.
- `aio_init`, `aio_submit_cmd`, `aio_multi_wait(num=1)`, `aio_multi_cancel`, `aio_multi_delete`.
- `osem_create` / `osem_delete` — real 128-zone kernel allocation.
- `aio_multi_wait(ids, num=2, states, mode=0, timeout=0)` returns `0x0` cleanly. **This is the Bagagwa arm.**

**Inert:**

- The arm returns success but no detector fires. Same result on two independent cold boots.
- `aio_debug_info` (syscall `0x2D7`, the Bagagwa writeup's leak) returns exactly four
  `0x00` bytes for `a1=ourPid`, ignores every other argument, and does nothing else
  across a sweep of 100+ shapes and 1M-sized count values.

**Dead:**

- `aio_get_data` (syscall `0x299`) OOMs the WebProcess on the first call with any
  arguments. Not usable from the browser on this firmware.
- 12.x `IPV6_RTHDR` validator refuses the pair (`EINVAL`). Cross-fd `getsockopt`
  returns `EINPROGRESS`, not the bug shape.
- `socketpair(AF_UNIX)` returns `EFAULT`; `pipe2` works as a fallback.

**Consequence:** the Bagagwa writeup's leak stage has no reachable path on 13.60.
Without a leak, the arm has no way to read the freed memory. The arm is
deterministic and clean; the measurement is missing.

---

## Hosting

Serve the directory. No build step. Works at a domain root or in a
subdirectory (GitHub Pages, `USER.github.io/REPO/`).

`.nojekyll` is required and present — without it Pages runs Jekyll and
silently drops `_`-prefixed paths.

### What does not work on GitHub Pages

The ELF tile menu cannot deliver payloads from a static host: the browser
has no raw sockets, and an HTTP POST to the console's `elfldr` on port
9021 would prepend HTTP headers so `elfldr` would not see `\x7fELF` at
offset 0.

Everything else works. If you need tile delivery, ship one of the
`api/payload` helpers (`payload.php` or `serve.js`) from a host that can
run PHP or Node. Or send ELFs yourself:
```

nc <ps5-ip> 9021 < payloads/etaHEN.elf

text

```
The remaining endpoints degrade safely: the one-shot latch falls back to
`localStorage`, progress beacons 404 inside `try/catch`, and the
`api/elfldr` probe is content-type guarded.

---

## Warnings

- P2JB spends about an hour on the leak stage with no output. That is normal.
- After a P2JB jailbreak, ending the WebProcess can panic the kernel. If a run
  aborts after stage 1, the page will tell you to power-cycle — follow it.
- Repeated panics degrade the console filesystem. If `fsck` reports `major>0`
  at boot, do a full power drain and consider Safe Mode → Rebuild Database.
- **13.60 AIO probe: do not call syscall `0x299`.** Every attempt OOMs the
  WebProcess and costs a browser restart. The result is recorded in
  `docs/FINDINGS.md`; there is no new information in re-running it.

---

## Layout

```
index.html landing page, firmware detection
p2jb.html engine boot; routes to a probe or the P2JB chain
poops.html Poopsploit entry

core.js mem.js int64.js WebKit primitive
main.js firmware gate, base derivation, module loader
rop-worker.js synchronous ROP syscall executor
rop.js rop_slave.js ROP chain builder + sacrificial worker
p2jb_lk.js per-firmware libkernel_web RVAs
p2jb_poops.js Y2JB adapter (defines window.syscall / read64 / ...)
p2jb.js P2JB kernel chain (12.00 – 12.70)
poops.js Poopsploit kernel chain (9.00 – 12.00)

bagagwa_probe.js the 13.60 Syscall test panel (all reachability tiles)
bagagwa_727probe.js standalone 0x2D7 sweep (13.60)
bagagwa_aio299probe.js 0x299 sweep — OOMs, kept for the record
bagagwa_aio299min.js single-shot 0x299 confirmation of the OOM
bagagwa.js kernel-stage scaffold (does not run; spec only)

offsets/ per-firmware offset tables (see docs/FINDINGS.md)
tools/ headless regression harnesses for the probe logic
payloads/ ELF payloads + the kexp shellcode blob
ui/ payload menu tile images
api/ optional payload handlers (not required to jailbreak)
docs/FINDINGS.md the 13.60 measurement record
```

---

## Testing

Three headless harnesses run the real probe inside a stubbed DOM. They
catch the failures that cost the first three hardware runs, including
the wrong `slot_expect` extrapolation, the mixed BigInt/Number delta
arithmetic, and the missing `states` argument on the armed call.

```
node tools/test_calibrate.mjs
node tools/test_convention.mjs
node tools/test_abimap.mjs
```

All three must pass before pushing any change to `bagagwa_probe.js`.

`tools/lkfind.js` is the static scanner for libkernel_web signatures. It
needs a real `.sprx`, which is why the runtime calibrate tile exists.

---

## Credits

- WebKit exploit chain, engine, ROP executor, P2JB, Poopsploit: **j0rdy** and
the slopkit lineage, via `soniciso1/pooP2JB`.
- P2JB kernel bug: **Gezine / cheburek3000**.
- Bagagwa bug description: publicly circulating writeup of unknown origin.
- 13.60 reachability study, calibrate tile, ABI map, the three harnesses, and
  this README: this repo.

See the creds block on `index.html` for the full list.

---

## Status

Active research, no working 13.60 kernel exploit. The userland stack is
complete and verified on 13.60. If a public 13.60 kernel exploit lands, the
harnesses under `tools/` and the calibrate tile are the fastest way to build
a new probe against it, and `docs/FINDINGS.md` records exactly which AIO
primitives are already excluded.

_Last updated: 2026-09-26._
