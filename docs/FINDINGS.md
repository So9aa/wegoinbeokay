# 13.60 findings

Scope: PS5 firmware 13.60, browser entry, WebKit → ROP → syscall reachability.
Operator: single-console, hardware-tested. Every claim below is a measurement,
not a derivation, unless tagged DERIVED. Nothing in this document asserts a
working jailbreak for 13.60 — there isn't one. What follows is the record of
what was checked and what the checks returned.

## Hardware

- Console: retail PS5, firmware 13.60 (Sony, unmodified).
- Entry: `index.html` → `p2jb.html?go=1&sc=1` (Syscall test).
- Executor: `rop-worker.js` + `bagagwa_probe.js`, `fireSync` synchronous mode.
- Kbase per boot: `0x8074c0000`, `0x812a94000`, `0x8222e0000`, `0x82525c000`,
  `0x836afc000` (five boots, all consistent within the 13.60 KASLR range).

## Verified working (VERIFIED)

Executed on hardware, returned clean, reproducible across multiple boots.

- WebKit primitive: userland half of `core.js`/`mem.js` completes; the
  `main.js` host-constructor base derivation produces a valid `libSceNKWebKitBase`.
- ROP syscall executor: `rop-worker.js` resolves the parked worker slot at
  `stack+0x7fc28` (12.00 parks at `0x7fc18`), `slot_expect=0x1988B`,
  `fired` counter increments through hundreds of chains.
- Raw errno convention measured: `close(0x7fffffff) -> 0x9 EBADF`, canary
  `getpid` alive after. `syscall_wrapper` is `mov r10,rcx; syscall; ret`,
  so ENOSYS reads `0x4e` (inferred from the convention, not measured).
- Identity family: `getpid`, `getppid`, `getuid`, `geteuid`, `getgid`,
  `getegid` — all return plausible values (`uid=0x1`).
- Descriptors: `kqueue` and `pipe2` return real fds (proven by `close()==0`).
- AIO family reachable: `aio_init`, `aio_submit_cmd(MULTI_READ, n=2, prio=3)`,
  `aio_multi_wait(ids, num=1)`, `aio_multi_cancel`, `aio_multi_delete` — all
  succeed.
- 13.60 libkernel_web row (in `p2jb_lk.js` group C) hardware-verified:
  `syscall_wrapper=0x1AEB7`, `setjmp=0x1D443`, `longjmp=0x1D49C`,
  `slot_expect=0x1988B`, `thread_list=0x6C218`.

## Measured but inert (VERIFIED)

The call returns success. Its intended effect does not occur.

### AIO ABI on 13.60

`aio_multi_wait` (syscall 0x297):

- `ids = arg1 (rdi)`, `num = arg2 (rsi)`, `states = arg3 (rdx)`.
- `arg3 (states)` is dereferenced whenever `num >= 1`. Passing NULL there
  is the sole cause of the EFAULT seen in earlier runs.
- `mode` and `timeout` positions are consistent with arg4/arg5 but the
  kernel does not act on them in any way we observed.

### The Bagagwa arm

With a real `states` buffer, `aio_multi_wait(ids, num=2, states, mode=0,
timeout=0)` returns `0x0` on 13.60. This is the first recorded success of
that call on this firmware.

Post-arm detection:

- 4 × `osem_create(WAKE0000..3)` succeeded (`0xa8..0xab`)
- 4 × `osem_create(SPRAY000..3)` succeeded (`0xac..0xaf`)
- wake write (`write(wfd,1)`) returned `0x1`
- All detectors (sentinel cells, WAKE name strings, witness block) unchanged
- cleanup (`cancel`/`delete`/`close`) all returned `0x0`

Result is reproducible. Two independent cold boots, identical outcome.

### osem

`osem_create(name,0,1,1,0)` returns a real handle (`0xa6..0xa8` across
runs). `osem_delete(handle)` returns `0x0`, proving the handle is genuine
kernel-side 128-zone allocation reachable from the browser.

## Measured dead (VERIFIED NEGATIVE)

### `aio_debug_info` (syscall 0x2D7, the Bagagwa writeup's leak)

Sweep: 100+ shapes, all argument positions, all count values 0..1M, all
prefill N=1..64 with matching `a2=N`, `aio_init` called with 7 argument
shapes, `a3` swept 0..0x80000000, `a4` swept 0..0xffffffffffffffff.

Result:

- `a1 = ourPid` is the only value that writes.
- Write is always exactly 4 bytes at `a5+0`, always `0x00000000`.
- `a2` (0..1M) has no effect. `a3` (any nonzero) has no effect. `a6` unused.
- `a4` must be in `[1, 0xffff]`; above that, EINVAL.
- Prefill N pending + completed with `a2=N` produces identical output.

Conclusion: on 13.60, 0x2D7 is a per-pid status getter. It does not leak.
The writeup's "dword at +0x20 plus two 8-byte pointers per element" does
not describe this firmware.

### `aio_get_data` (syscall 0x299)

Single-call probe. Two `getpid` canaries. `aio_init(pid,0)` first.

```
canary1 getpid=0x78
aio_init(pid,0) -> 0x0
canary2 getpid=0x78
about to call 0x299(0,1,1,1,out,0) ← last persisted line, then OOM
```

The `0x299` call with `a1=0` and any valid out buffer triggers
"There is not enough free system memory" in the WebProcess. The kernel
accepted the call (no EFAULT, no error) and its internal allocation
exceeded the browser process RSS budget before the call returned.

Reproduced with `a1=0`, `a1=ourPid`, `a1=id0`, three different out-pointer
sizes (0x40, 0x400, 0x4000). Every attempt OOMs.

Conclusion: 0x299 is unusable from the WebProcess on 13.60. There is no
argument shape that makes the call cheap, and no smaller buffer avoids
the OOM because the allocation is internal to the kernel side of the
call.

### Kernel bugs from the 12.x chains

Called for real, read-only, closed again:

- `setsockopt(IPPROTO_IPV6=41, IPV6_RTHDR=51, tag, 0x38)` → `0x16 EINVAL`.
  The 13.x validator refuses the pair.
- `setsockopt(IPPROTO_IPV6, IPV6_FL_AUDIT=0x6d, ...)` → `0x2a ENOPROTOOPT`.
  Option code 0x6d is not recognized on 13.60.
- `getsockopt(victim-pipe-fd, IPV6_RTHDR)` → `0x26 EINPROGRESS`. The
  cross-descriptor bug shape returns a protocol error, not zero. Dead.
- `socketpair(AF_UNIX, SOCK_STREAM)` → `0xe EFAULT`. AF_UNIX socketpair is
  gated in the WebProcess sandbox; `pipe2` works as a fallback.
- `getrlimit(RLIMIT_NOFILE)` → `0x0`, `cur=13952`.

The 12.x kernel-bug surface answers but every bug shape is refused.
Consistent with psdevwiki's "P2JB patched since 13.00".

## What this means

On 13.60, the AIO family exposes the primitives the Bagagwa writeup names
— `aio_multi_wait` with a real `states` buffer accepts `num=2` and returns
success — but the writeup's leak stage is unreachable: `0x2D7` returns a
constant zero dword, and `0x299` OOMs the process on the first call.

Without a leak there is no way to read the state of the freed waiter
array after the arm. The arm itself is deterministic and clean; the
measurement is not available.

The 12.x chain primitives (`IPV6_RTHDR` validator bypass, cross-fd
`getsockopt`) are refused on 13.60 and match the psdevwiki patch notes.

There is no path from this stack to a kernel primitive on 13.60 as of
2026-09-26.

## Files in this repo, by role

- `bagagwa_probe.js` — the panel. Loaded by `p2jb.html?sc=1`. Every tile
  read-only except the ARM tile (`?arm=1` gate).
- `bagagwa_727probe.js` — standalone 0x2D7 sweeper. Auto-runs.
- `bagagwa_aio299probe.js` — 0x299 sweep (OOMs; retained for the record).
- `bagagwa_aio299min.js` — single-shot 0x299 test. Confirms the OOM.
- `p2jb_lk.js` group C — the hardware-verified 13.60 libkernel_web row.
- `tools/test_calibrate.mjs`, `tools/test_convention.mjs`,
  `tools/test_abimap.mjs` — headless regression suites for the probe
  logic. All three run the real probe inside a stubbed DOM.

## Hardware-verified vs derived vs upstream

| item | tag |
|---|---|
| All 13.60 libkernel_web RVAs | VERIFIED (calibrate tile) |
| 13.60 `thread_list = 0x6C218` | VERIFIED (`find_worker` succeeded) |
| `aio_multi_wait` ABI `(ids, num, states, mode, timeout)` | VERIFIED (ABI map) |
| `aio_multi_wait(num=2, states)` returns 0x0 | VERIFIED (two arms) |
| `osem_create/delete` real handle | VERIFIED |
| `0x2D7` writes 4 zero bytes | VERIFIED (100+ shapes) |
| `0x299` OOMs on first call | VERIFIED (three attempts, three boots) |
| 12.x `IPV6_RTHDR` validator patched | VERIFIED |
| ROP executor mechanics | VERIFIED (`fired` counter, poison test) |

## What is not in this document

- No KASLR slide derivation on 13.60. Kbase changes per boot; the
  executor re-resolves it via the parked worker stack.
- No kernel data offsets. `offsets/13.60.js` has none, deliberately.
  All four `DATA_BASE_*` values are unknown for this firmware.
- No working kernel R/W primitive. Every route tried is in this document.
- No jailbreak.

## If you pick this up

The most valuable things to preserve are the three harnesses under
`tools/` and the calibrate tile. They are the only way to reproduce a
measured `slot_expect` on any 13.xx firmware from a parked worker stack,
and they catch the exact failures that cost the first three runs
(wrong `slot_expect`, mixed BigInt/Number in delta arithmetic, the missing
`states` argument on the armed call).

Do not re-run `0x299`. Do not re-arm the UAF without a leak path. Both
answers are recorded above and further runs cost WebProcess restarts with
no new information.

_Last updated: 2026-09-26._
