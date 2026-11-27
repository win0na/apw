# Native ADI: feasibility findings

Status: implemented. The gate below failed for Apple's binary, then a native
MIT implementation (`apple-auth`) was found and ported to Rust. See Outcome at
the end.

Date: 2026-11-26. Branch: `native-adi`. Apple ADI binary analysed:
`CoreADI-26.x86_64`, SHA-256 `4b6b320f…a5dae1` (the build pinned by
`anisette-server-rs` 0.2.1).

## What "native ADI" would require

apw needs two things from Apple's ADI stack:

1. **Provisioning.** Ask Apple for a machine identity, exchange `spim`/`cpim`
   with the gateway, then `ptm`/`tk`, and persist the opaque result (`adi.pb`,
   664 bytes).
2. **OTP.** On every request, derive `X-Apple-I-MD` from the provisioned state
   and the current time. The value is 24 or 28 bytes:

   ```
   u32 type | u32 0x00000010 | 16 OTP bytes [| u32 platform tail]
   ```

   The first word selects the variant by DSID: `4` with no tail for DSID -1
   (24 bytes), `5` with a platform tail for DSID -2 (28 bytes). The 16-byte
   field changes exactly on 30-second boundaries.

Provisioning is gated behind the same binary and the same obfuscation, so a
native OTP is a prerequisite for native provisioning, not a separate task.

## Method

The pinned emulator (`adi-macos`, a GPL-2.0-only research fork kept outside the
repository) was instrumented with three additions:

- a full guest memory-access trace with read and write values, plus the RIP of
  each access;
- an import log with arguments, to tell host-side writes from guest writes;
- an injectable clock (`ADI_FAKE_TIME`) so one state can be queried at arbitrary
  times.

With that, a single `OP_REQUEST_OTP` (ADI opcode `0xcfe0b46a`) can be traced end
to end. Results were checked against the live `anisette-server-rs` container.

Parity was confirmed before drawing conclusions: given the same provisioned
state and the server's own `X-Apple-I-Client-Time`, the emulator produced a
byte-identical `X-Apple-I-MD` (`00000005000000104b9e151d…a9e02980000001`,
device `19FFDEED-97ED-35AE-14DF-819F442D6E99`, window 2026-11-26T21:39:07Z).
The traces therefore describe the same computation the service performs.

## Result: the OTP is a proprietary white-box primitive

The 16 OTP bytes are not produced by any standard primitive reached from the
provisioned state or from runtime memory.

### Where the bytes are produced

In the guest, the 16 OTP bytes land at guest heap `0x400207e8`. They are written
by a flattened assembly block at guest VA `0x100125a80`–`0x100125c36`. That block
takes four 32-bit registers, extracts each byte with a different XOR/subtract
mask, and stores the result. The four registers are fed by earlier code that
reads single bytes from several runtime tables and mixes them with stack slots.

The ADI reply is then assembled at `0x4002c9d5`–`0x4002ca13` as an XOR-`0x34`
encoded string by code at `0x10021a1e0`, and decoded into the XPC reply buffer
at `0x1001d4d00`.

### Obfuscation observed

- Control flow is flattened: basic blocks end in
  `movsxd rax,[table+index*4]; lea rdx,[rip-x]; add rax,rdx; jmp rax`, with
  opaque predicates feeding the index.
- Constants used by the OTP path are not plaintext: the store block masks every
  byte, and the reply is XOR-encoded until the last software layer.
- No AES S-box, AES T-tables, SHA-1/256/512 or MD5 constants, ChaCha sigma, SM4
  S-box, DES S-box, or AES-NI/SHA extension opcodes appear in the Mach-O. The
  same holds for the Windows PE (KERNEL32-only imports, two exports, no crypto
  DLL).
- The 256-byte table candidates read during the final assembly are not
  permutations and do not match AES, inverse AES, or SM4.

The Android build (`libCoreADI.so`, aarch64, NDK r19b) shows the same toolchain
family: flattened blocks dispatched from `ldrsw` jump tables with computed
indices, junk constant chains, `+0x11`-obfuscated strings, and an encrypted
`.rodata` (entropy 7.87). It contains no AES/SHA/SM4/ChaCha tables and no ARMv8
crypto instructions (0 in 369,602 decoded instructions). Its advantage is
interface, not code: `libstoreservicescore.so` loads it with `dlopen` and
`dlsym`s two plain C exports, `int cvu8io98wun(void *ctx)` and
`int vdfut768ig(int op, void *ctx)`. That makes an aarch64 Unicorn oracle cheap
to build, but the primitive remains obfuscated.

The Windows build (`CoreADI.dll`, PE32+ x64) is the same protection class. Its
PDB path names a `fairplay_release` build; both exports are gibberish names; the
372 KB worker is flattened the same way and mixes in heavy mixed-boolean
arithmetic (8,394 `imul`, 5,327 `xchg`, 4,436 `adc` in one function). It has no
plaintext AES/SHA/ChaCha/SM4 constant, no AES-NI, and no 256-byte table that
matches a known S-box. Thirteen 256-byte permutation tables exist in `.rdata`
with no match to AES, SM4, or DES, so they are either obfuscator maps or an
unknown primitive's tables.

One useful structural fact: the Windows DLL has no clock read of its own. Its
only `GetSystemTimeAsFileTime`/`QueryPerformanceCounter` calls are in the CRT
security-cookie initialiser, so the time is passed in by the caller, like the
30-second cadence in the macOS guest.

### Negative primitive search

One provisioned macOS state was queried at `t = 1000000000`, `1000000031`, and
`1795728358`; three distinct OTPs were returned, confirming time dependence.

Two time windows were then used as a known-answer pair. The following were
tried against both OTPs, with keys drawn from every stable, non-trivial 16-,
32-, and 64-byte window of the emulator heap, stack, `__DATA`, and scratch
arenas (809,985 keys):

- AES-128/192/256 decrypt and encrypt, with a structural test for a 4- or 8-byte
  counter/time field that differs by one step between the two windows;
- HMAC-SHA256, HMAC-SHA1, HMAC-MD5 over 4- and 8-byte big- and little-endian
  encodings of seconds and of the 30-second counter, plus decimal ASCII;
- SHA-256, SHA-1, and MD5 over `key || message` and `message || key`.

Zero matches. The earlier pass had already ruled out AES, HMAC, and hash
constructions over the raw `adi.pb` windows and over the identifier, host UUID,
MID, and their SHA-256 digests.

This is consistent with the OTP being computed by an obfuscated, keyed
permutation whose key material is itself derived inside the binary, not with a
standard cipher applied to a key we can reach.

## Public prior art

Every public anisette implementation found wraps an Apple binary: Provision,
anisette-v3-server, anisette-server-rs, omnisette, Anisette.py, anisette-js,
swift-anisette, os-findmy-e, MacADICore, and xadi. None contains an OTP
generator.

What is documented publicly is the protocol, not the primitive:

- The ADI C API and its calling convention (`ADILoadLibraryWithPath`,
  `ADIOTPRequest`, `ADISetProvisioningPath`, the `ADICall` request struct, the
  magic values `0x632b8d6e`/`0x85fe63b0`), in ionescu007/Blackwood-4NT (the
  sections on OTP and MID are deliberately empty).
- The provisioning exchange (`spim` -> `cpim` -> `ptm`/`tk`) as opaque blobs,
  and the `adi.pb` path; no `adi.pb` format and no key agreement are published.
- The claim, from Provision's own docs and Blackwood-4NT, that CoreADI is
  "obfuscated with FairPlay techniques". No unpacked build, annotated database,
  or identified primitive (AES, white-box AES, SM4, ARX) is public.

So a reimplementation would start from zero against at least five divergent
platform builds, and the one researcher who reached the API level explicitly
withheld the algorithm.

## What this means

A from-scratch implementation has to reverse Apple's obfuscated primitive:
recover the key-derivation path from `adi.pb`, deobfuscate the arithmetic, and
prove header parity against Apple's servers for every backend. That is a
research project measured in weeks or months, with a real chance of failure.
It is not a packaging change and not a bounded feature.

The prior art review (running in parallel at the time of writing) is expected to
confirm that no public project has done this; every shipped anisette server
wraps an Apple binary.

## Options that meet the stated constraints

The constraints were: no Apple binaries in apw's package, and no download by apw
at first run or first install.

1. **External service, user-supplied.** apw already accepts `anisette_url`
   (and `APW_ANISETTE_URL`). apw ships no Apple bytes and downloads nothing.
   The user runs a server however they prefer: the Nix package, the upstream
   container, or a remote host. This is the only option that is fully compliant
   today and needs no new primitive.
2. **Web sign-in instead of device ADI.** `idmsa.apple.com` browser login does
   not require anisette headers. Whether the resulting tokens grant the
   keychain/escrow services apw needs is unverified and needs one real account
   login to test. If it works, ADI disappears for the login path; if it does
   not, escrow still needs a device identity.
3. **Continue the reverse engineering** as a separate, time-boxed effort with a
   go/no-go on recovering the primitive. Nothing in this pass suggests a quick
   win.

Recommendation: take 1 for packaging and correctness now, and test 2 with a
real account before investing further in 3. The `native-adi` branch should not
merge an incomplete primitive.

The concrete next experiment for 2 is `icloud.com/passwords` (Apple's web
Passwords app) and `idmsa.apple.com` browser sign-in: both work without
anisette headers. If a web session can read the keychain records, apw's escrow
step disappears along with ADI; if not, escrow still needs a device identity
and option 1 was the answer. That test needed one interactive account login,
so it could not run unattended.

## Reproduction

The research harness lives outside the repository because it is derived from
GPL-2.0-only code and apw is GPL-3.0-only:

```
/tmp/opencode/ani/src                 patched adi-macos emulator
/tmp/opencode/ani/mac-state.json       provisioned macOS state snapshot
/tmp/opencode/ani/identity-macos.json  server-exported identity (adi_pb is the
                                       state snapshot, base64)
```

Commands (from `/tmp/opencode/ani`):

```sh
# parity with the live macOS service on 127.0.0.1:6971: fetch its headers,
# then replay the same window through the emulator
curl -s http://127.0.0.1:6971/ | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print(d["X-Apple-I-Client-Time"], d["X-Apple-I-MD"])'

# three distinct OTPs from one state
for T in 1000000000 1000000031 1795728358; do
  ADI_FAKE_TIME=$T ./src/target/release/examples/capture \
    rootfs/assets/CoreADI-26.x86_64 mac-state.json \
    19ffdeed97ed35ae14df819f442d6e99 /tmp/opencode/ani/tq | grep OTP
done

# memory trace of one request (magic 1 = code, 2 = memory)
ADI_TRACE=/tmp/trace.bin ADI_TRACE_MODE=2 ADI_TRACE_MAX=3000000 \
  ADI_FAKE_TIME=1795728358 ./src/target/release/examples/capture \
  rootfs/assets/CoreADI-26.x86_64 mac-state.json \
  19ffdeed97ed35ae14df819f442d6e99 /tmp/opencode/ani/trace | grep -E 'TRACE|OTP'
```

The trace format is a text header (`ADI1 …`) followed by 1-byte tags: `0` for
a code event (`rip`, `rsp`, both `u64` LE) and `1` for a memory event (`access`,
`size`, `address`, `value`, `rip`).

## Limits

- Only the macOS backend was traced end to end. The Windows and Android
  libraries are separate builds with the same lineage; Android was reviewed
  separately.
- The negative search covers standard constructions with reachable keys. It
  cannot prove that no exotic composition works, only that nothing obvious does.
- The live Apple gateway was not contacted in this pass; parity was measured
  against the pinned service, which is itself a wrapper over the same binary.

## Update 2026-11-26: the primitive is public and works

The earlier conclusion ("not reproducible") was wrong. A catalog search that
started from Apple's clients rather than from the anisette-server ecosystem
found [`apple-auth`](https://github.com/apple-auth/apple-auth): C++20, MIT,
"runs without emulating Apple libraries". Its `src/adi` is a native
implementation of the same primitives: state container, key derivation, OTP,
and provisioning. Every public anisette server reviewed earlier wraps Apple's
binary; this project does not.

Evidence, collected in an Ubuntu 24.04 container with only Mbed TLS installed:

- `APPLE_AUTH_WITH_CLIENT=OFF` builds `libapple_auth.so` from `src/adi` and
  `src/crypto` (Mbed TLS 2.28). No Apple file is read at build or run time.
- `apple-auth provision dev-mac --device mac` and `--device windows` both
  completed against `gsa.apple.com` on 2026-11-26 and wrote `adi.pb` plus
  `identity.json` (636 bytes / 444 bytes). Provisioning validates the
  start, finish, and decode profiles.
- A GrandSlam `init` request built with headers from the native profile
  (random `A2k`, no password) returned HTTP 200 with `s`, `i`, `B`, and `c`.
  Apple accepted the `X-Apple-I-MD` and `X-Apple-I-MD-M` values, so the OTP is
  correct, not merely well-formed.
- The OTP envelope matches the service byte layout: `u32 5 | u32 16 | 16
  bytes | u32 platform` (platform 1 for Mac, 2 for Windows).

The license route is clean: MIT code can be linked into or translated into
GPL-3.0-only apw with the copyright notice. No clean-room pass is needed, and
no Apple binary is distributed.

`src/adi` is about 4,500 lines for Mac and Windows GrandSlam only, once
Android and Store paths are dropped. The plan is a Rust translation under
`src/adi/` with these stages:

1. State container and key derivation, validated against `adi.pb` files
   produced by the C++ implementation.
2. Key recovery and OTP, validated at fixed counters.
3. Provisioning, validated against Apple live.
4. Wire `identity_for` to the native provider, keeping `anisette_url` as the
   user override.

Oracle vectors (25 counters for a Mac and a Windows device, plus machine IDs)
are at `/tmp/opencode/oracle/vectors.json`; the reference binary is
`/tmp/opencode/apple-auth/build2/apple_auth_otp_at`.

## Outcome (2026-11-26)

The port is implemented. `src/adi/` is a Rust translation of the MIT
`apple-auth` ADI core, with the MIT notice in `src/adi/LICENSE-MIT`. It loads no
Apple binary and downloads nothing. Scope is GrandSlam macOS and Windows.

Evidence:

- 150 OTP vectors (6 provisioned profiles × 25 counters) are byte-exact, in
  `tests/fixtures/adi/profiles.json`.
- The masked parameter tables were re-derived independently and match the C++
  arrays byte for byte. 26 counters outside the fixture also match the reference
  binary.
- `tests/fixtures/adi/provisioning.json` holds a captured macOS and Windows
  provisioning exchange. The Rust code reproduces the CPIM, machine ID,
  secondary state, encrypted seed, extra data, and OTPs exactly.
- Live GSA accepts fresh native identities for both platforms: the response
  carries `hsc = 200`, which is the device-identity status. A zeroed proof in
  the same request returns `hsc = 401`. Apple reports the placeholder account
  separately as `ec = -20970`, so the device check is independent of the
  account.
- Re-run with `APW_LIVE_ADI=1 cargo test --test adi_live -- --ignored`.

`apw` provisions on first sign-in and stores the decoded state in
`$XDG_STATE_HOME/apw/adi/{macos,windows}.json` with mode 0600. `APW_ANISETTE_URL`,
`--anisette-url`, or `anisette_url` selects an external server instead. The Nix
anisette package and the systemd unit are removed on this branch.

Not ported: the Store and Android profile paths, and the `adi.pb` container
format, which only obfuscates the same decoded fields with a hardware-derived
file key.

## Escrow identity (2026-11-26)

The shipped client mints the escrow PET on the Windows chain and sends the
Windows claim with it. That works, but "escrow requires Windows" is not
established. The evidence points to a platform-consistency rule instead.

- The escrow proxy authenticates with Basic `apple-id:PET`, where PET is
  `com.apple.gs.idms.pet` from GrandSlam, with anisette headers and the sbd user
  agent (`com.apple.sbd/638.100.48 com.apple.iCloudHelper/282`), client info
  `...<com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>`, and
  `x-apple-i-device-type: 1`.
- A macOS-minted PET sent with Windows client info and a Windows proof returns
  `-3001 Authentication failed` for every credential pair. The same request
  with the Windows PET succeeds. Community tables report the same failure for a
  Mac claim with Windows ADI, and other mismatch codes (`-80045`, `-22410`) when
  the ADI library and the advertised platform disagree.
- Apple's open-source `escrowrequest` and `TrustedPeersHelper` enroll macOS as a
  first-class escrow client (`device_platform = 2`), and working Rust clients
  have sent a Mac claim. No public source shows a server-side Windows-only gate.
- Unverified: a full macOS-ADI recovery after Apple's October 2026 change. No
  public report confirms or denies it.

Experiment, needs one interactive sign-in: force a macOS two-factor challenge
(`request_trusted_device` plus a code) so Apple mints a macOS PET, then call
`GETRECORDS` with the macOS claim and that PET. A 200 removes the Windows
identity, the second code, and half the state. Until then the Windows path is
the tested one.
