# RAR4 fixtures written by a real archiver

The sibling `testdata/rar4/` fixtures come from the vendored rars fork's
own RAR4 writer (`vendor/rars/src/rar15_40/write.rs`). They are real
bytes and they pass `unrar t`, but that proves the WRITER valid, not the
READER complete: a header field our writer never sets is a field our
reader has never been tested on, and nothing would report that.

These come from RARLAB archivers instead, so the field combinations are
whatever the archiver chose rather than whatever we know how to emit.
Every one was validated with the reference decoder before committing:

```
unrar t [-ptestpw123] <archive>
```

Two producers, because they differ in what they put in a header - the
host-OS byte, and (the reason `win-fullwidth*` exist) how the
`FHD_UNICODE` name encoder builds its fallback:

| prefix | archiver | host |
| --- | --- | --- |
| `mac-` | RARLAB `rar` 6.24 for macOS arm64 (3 Oct 2023), `-ma4` | Unix |
| `win-` | RARLAB `Rar.exe` 6.24 x64 for Windows (WinRAR 6.24), `-ma4` | Windows |

`rar 7.x` cannot write RAR4 at all (`-ma4` is gone: `ERROR: Unknown
option: ma4`), which is why 6.24 was fetched for this. Payloads are
1000 bytes (`inner.bin`) for the single-volume shapes and 2800 bytes
(`split.bin`) for the volume sets; neither is 16-byte aligned, so an
encrypted data area is padded and a plaintext one is not.

| file | switches | what it pins |
| --- | --- | --- |
| `mac-store.rar` | `-m0` | baseline single-volume store, and the end-of-archive block a real archiver writes (our own writer emits none) |
| `mac-oldvol.{rar,r00,r01,r02}` | `-m0 -v1000b -vn` | old-style `.rar`/`.r00`/`.r01` naming as actually posted; per-fragment CRC32 on every volume but the last, whole-file CRC32 on the last |
| `mac-rr-comment.rar` | `-m0 -rr5p -z` | a recovery-record sub-block and an archive-comment sub-block, both skipped, with the member's data offset pushed past them |
| `mac-unicode.rar` | `-m0` | `FHD_UNICODE`, encoder modes 0/1/2 and a mode-3 run WITHOUT a correction byte. The `.bin` name's non-BMP character decodes to `U+F4E6`: the archiver truncated `U+1F4E6` to 16 bits when it wrote the field, and unrar reads back the same lossy name, so matching it is parity and not a defect |
| `mac-large-tail.r03` | `-m0 -v1g -vn` | `LHD_LARGE`: the FINAL volume of a >4 GiB split store. `unp_size` is 4294967303, so the header carries the 8 extra high-half bytes and every field after them is shifted. 477 bytes, because the other four volumes of that set are 1 GiB each and are not committed - this volume is the whole point of the shape |
| `win-store.rar` | `-m0` | the same baseline from the Windows host, whose header differs in the host-OS byte |
| `win-fullwidth.rar` | `-m0` | mode-3 run WITH a correction byte - the one name-decoder branch no Unix-written archive reaches, because rar on macOS writes the raw UTF-8 as the fallback while WinRAR writes a code-page conversion. Fullwidth Latin best-fits to ASCII, so the wide low byte tracks the fallback byte at a constant `-0x20` under a constant high byte `0xFF`, which is exactly the run the encoder codes that way |
| `win-fullwidth-long.rar` | `-m0` | the same branch at its MAXIMUM run length: a 140-character name codes as a 129-unit correction run (the `(len & 0x7f) + 2` ceiling) followed by an 11-unit one |
| `win-oldvol.{rar,r00,r01,r02}` | `-m0 -v1000b -vn` | the Windows-written split, including a middle volume that is split on both sides |
| `win-enchdr.rar` | `-m0 -hptestpw123` | `-hp` from a real archiver: encrypted headers, salt + AES padding around the header, `MHD_PASSWORD` on a plaintext main header |
| `win-encvol.{rar,r00,r01,r02}` | `-m0 -ptestpw123 -v1000b -vn` | encrypted split: one AES-128-CBC stream across four volumes with the salt repeated in every volume's header. Its last volume's CRC32 equals `win-oldvol.r02`'s, which is the same payload unencrypted - the proof that RAR4's stored whole-file CRC is of the PLAINTEXT |

Password on every encrypted fixture is `testpw123`, matching
`testdata/rar4/`.
