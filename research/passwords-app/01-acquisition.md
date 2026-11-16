# 01. Acquisition: from IPSW to readable binaries

All commands below were run on x86_64 Linux. Paths are from the working tree used
for this research; they are not part of the repository.

## 1. Image identity

| Field | Value |
|---|---|
| URL | `https://updates.cdn-apple.com/2026FallFCS/a75ca3b6-83d4-440d-99fc-99ecb7406750/iPhone17,1_27.2.1_24B156_Restore.ipsw` |
| Bytes | 12,992,259,527 |
| SHA-256 | `e2916731a8d655d3d2d5aec75ebab1fde569a2fe3aa01092ac096d75582bea8d` |
| `ipsw info` | version 27.2.1, build 24B156, Production |
| Device | iPhone 16 Pro (iPhone17,1), board D93AP, t8140, timestamp 2026-10-13 |

The hash matches the value published by `api.ipsw.me` for this build.

## 2. What is inside

The IPSW is a zip of seven DMGs plus firmware payloads. `BuildManifest.plist`
names them:

| File | Manifest key | Size | Role |
|---|---|---|---|
| `141-08301-224.dmg.aea` | `OS`, `SystemVolume` | 9.13 GB | root filesystem (read-only OS volume) |
| `141-08380-243.dmg.aea` | `Ap,ExclaveOS` | 528 MB | Exclave OS |
| `141-08824-252.dmg` | `Cryptex1,AppOS` | 16 MB | app cryptex, plain, tiny |
| `141-09160-233.dmg.aea` | `Cryptex1,SystemOS` | 2.42 GB | system cryptex, holds frameworks and the dyld cache |
| `141-09277-246.dmg.aea` | `OS` (Recovery) | 260 MB | recovery install variant |
| `141-09491-250.dmg` | `RestoreRamDisk` (Upgrade) | 247 MB | restore ramdisk |
| `141-10399-248.dmg` | `RestoreRamDisk` (Erase) | 245 MB | restore ramdisk |

`Cryptex1,AppOS` is not where system apps live. It contains notification bundles
and small system resources; it has no `Applications` directory. The Passwords app
is in the root filesystem.

## 3. Decrypting the AEA DMGs

AEA1 DMGs in an IPSW are encrypted with a key that `ipsw` can derive from the AEA
header; no Apple authentication or personalization is involved.

```sh
# extract the encrypted image from the zip
unzip -o -q iPhone17,1_27.2.1_24B156_Restore.ipsw 141-08301-224.dmg.aea -d fs/
unzip -o -q iPhone17,1_27.2.1_24B156_Restore.ipsw 141-09160-233.dmg.aea -d sys/

# inspect and derive the symmetric key
ipsw fw aea -i fs/141-08301-224.dmg.aea
ipsw fw aea -k fs/141-08301-224.dmg.aea
# -> base64:hDfX+AURfU+BcBhPeW1os0lJkaNOVc75NAfiSbR0u4w=

# decrypt
ipsw fw aea -b '<base64-key>' -o fsout/ fs/141-08301-224.dmg.aea
ipsw fw aea -b '<base64-key>' -o sysout/ sys/141-09160-233.dmg.aea
```

Both images decrypted with the pure-Go AEA implementation. Output sizes: 9.8 GB
for the root filesystem, 6.0 GB for the system cryptex.

The `-k` value is an archive key, not a device key. It differs per DMG; derive it
for each file.

## 4. Reading APFS on Linux

`7z` 26.00 reads APFS directly and is the fastest way to list and extract files:

```sh
7z l -ba fsout/141-08301-224.dmg | grep -i 'Passwords'
7z x -y  fsout/141-08301-224.dmg 'private/var/staged_system_apps/Passwords.app/*' -oapp/
```

Two limits matter:

- **`7z` does not decompress decmpfs.** Compressed files come out as zero-byte
  files plus `name:com.apple.decmpfs` and `name:com.apple.ResourceFork` siblings.
  `Info.plist` files in frameworks hit this.
- **`ipsw extract --files` needs `apfs-fuse`.** It mounts the DMG and fails with
  `failed to find apfs-fuse` otherwise. It also selects the AppOS image first for
  some patterns, which is not where the app is.

Build `apfs-fuse` for full reads:

```sh
git clone --depth 1 --recurse-submodules --shallow-submodules \
  https://github.com/sgan81/apfs-fuse
# GCC 15 needs <cstdint> in ApfsLib/PList.h
sed -i '5i #include <cstdint>' apfs-fuse/ApfsLib/PList.h
cmake -S apfs-fuse -B apfs-fuse/build -DUSE_FUSE3=ON \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make -C apfs-fuse/build -j8
```

`-DCMAKE_POLICY_VERSION_MINIMUM=3.5` is required with CMake 4.x. The submodules
matter: without them the build fails at `No SOURCES given to target: lzfse`.

Mount and read:

```sh
apfs-fuse -o vol=0 fsout/141-08301-224.dmg /mnt/ios-fs
ls /mnt/ios-fs/root/private/var/staged_system_apps/Passwords.app
python3 -c "import plistlib; print(plistlib.load(open('/mnt/ios-fs/root/.../Info.plist','rb')))"
```

The mounted volume has `root/` and `private-dir/` at the top. Everything lives
under `root/`. `apfs-fuse` decompresses decmpfs transparently, which is why
`Info.plist` reads correctly here and not from `7z`.

## 5. The dyld shared cache

Most framework Mach-Os are not on disk. They exist only in
`System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e` inside the system
cryptex. Extract the cache files with `7z`, then read them through the
`apfs-fuse` mount. Do not feed the `7z` output to `ipsw dyld`:

- `dyld_shared_cache_arm64e.81.dyldlinkedit` is decmpfs-compressed. `7z` writes a
  zero-byte file plus a 195 MB resource fork, and `ipsw dyld` then fails with
  `invalid argument` while parsing the cache.
- The mounted file is the decompressed stream; `ipsw dyld` parses it.

```sh
ipsw dyld info --dylibs /mnt/ios-fs/root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e
ipsw dyld extract <dsc> /System/Library/PrivateFrameworks/PasswordManagerUI.framework/PasswordManagerUI -o fw/
ipsw class-dump <dsc> /System/Library/Frameworks/Security.framework/Security > Security.classdump.txt
```

`ipsw class-dump <macho>` fails on a cache-extracted dylib with `no file data at
address …`. Use the two-argument form with the cache path and the image path.
`securityd` is a normal file in the root filesystem, so `ipsw class-dump securityd`
works directly.

## 6. Artifacts used for the analysis

| Artifact | Path in the extracted tree | Size | SHA-256 |
|---|---|---|---|
| Passwords app executable | `app/private/var/staged_system_apps/Passwords.app/Passwords` | 154 KB | `b1acda2ae49c4dbe50c2c844579e29bbd3fd187a8c0093e44989e23ef8d0de90` |
| PasswordManagerUI | `fw/PasswordManagerUI` | 9.6 MB | `165177f017548e73b84f64111494f5de984c2f8496556e36d6e32da80b7cc829` |
| securityd | `bin/securityd` | 4.1 MB | `ec612e78788787b6dd7ebabb96a1c8d950b44cad41979fef9d875aac5288c58c` |
| keychainsharingmessagingd | `bin/keychainsharingmessagingd` | 213 KB | `041a6c4f1706c6552c398f4539287c7f235d28ba91e5ad3879dec0d1ae0190ed` |
| Security.framework | `fw/Security` | 3.1 MB | (cache extraction) |
| CloudKit.framework | `fw/CloudKit` | (cache extraction) | (cache extraction) |
| ProtectedCloudStorage | `fw/ProtectedCloudStorage` | 1017 KB | (cache extraction) |

Tool versions: `ipsw` 3.1.749 (`a7dfadbcaca8375b424c12a68dae40767e5e07c1`),
7-Zip 26.00, `apfs-fuse` `66b86bd`.

## 7. Traps worth remembering

1. A 13 GB IPSW does not fit in a 12 GB `/tmp` tmpfs. Use a real disk.
2. `nohup … &` inside a tool-invoked shell dies when that shell exits. Use the
   runner's background mode for long downloads, and resume with `curl -C -`.
3. `ipsw extract --dmg sys` copies the `.aea` file; it does not decrypt it.
4. `ipsw info -k` tries to fetch every key from theapplewiki and fails on the
   first missing one (`DeviceTree`). `ipsw fw aea -k` is the reliable path for
   the DMGs.
5. `7z` lists APFS directories and file sizes but returns compressed content for
   decmpfs files. Use `apfs-fuse` for anything you need to parse.
6. `ipsw dyld` needs the whole split cache, including `.dyldlinkedit`. A cache
   assembled from `7z` output is not parseable.
