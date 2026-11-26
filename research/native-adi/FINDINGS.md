# Native ADI: feasibility findings

Status: gate failed. Native OTP generation is not reproducible from public
information or by searching standard primitives.

Date: 2026-11-26. Branch: `native-adi`. Apple ADI binary analysed:
`CoreADI-26.x86_64`, SHA-256 `4b6b320f…a5dae1` (the build pinned by
`anisette-server-rs` 0.2.1).

## What "native ADI" would require

apw needs two things from Apple's ADI stack:

1. **Provisioning.** Ask Apple for a machine identity, exchange `spim`/`cpim`
   with the gateway, then `ptm`/`tk`, and persist the opaque result (`adi.pb`,
   664 bytes).
2. **OTP.** On every request, derive `X-Apple-I-MD` from the provisioned state
   and the current time. The value is 28 bytes:

   ```
   u32 0x00000005 | u32 0x00000010 | 16 OTP bytes | u32 platform tail
   ```

   The 16-byte field changes exactly on 30-second boundaries.

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
