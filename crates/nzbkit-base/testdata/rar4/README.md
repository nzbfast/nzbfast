# RAR4 encrypted fixtures (password `testpw123`, payload `secret.bin`)

`rar 7.x` can no longer CREATE RAR4 archives, so these come from the
vendored rars fork's RAR4 writer (`vendor/rars/src/rar15_40/write.rs`).
Each one was validated with the reference decoder before being committed:

```
unrar t -ptestpw123 <archive>
```

passes on all four shapes. The split sets are numbered `.partN.rar` here
for the tests' convenience; unrar wants old-style `.rar`/`.r00`/`.r01`
names, which is how they were checked.

| file | shape |
| --- | --- |
| `enc-store.rar` | `-m0 -p` single volume (plaintext headers, AES-128 data) |
| `enc-vols.part{1,2,3}.rar` | `-m0 -p` split - ONE CBC stream across the three |
| `enc-hdrs.rar` | `-m0 -hp` single volume (encrypted headers AND data) |
| `enc-hdr-vols.part{1,2,3}.rar` | `-m0 -hp` split |

That provenance is also this directory's limit: the reader only ever
meets field combinations our own writer knows how to emit, so `unrar t`
accepting them proves the WRITER valid, not the reader complete. The
shapes an actual archiver chose live in `testdata/rar4-archiver/` -
plain stores, old-style `.rar`/`.r00` volume naming, a recovery record,
an archive comment, `LHD_LARGE` past 4 GiB, and the unicode-name
correction run only WinRAR emits.

The facts the one-pass mapper rests on and these pin: `unp_ver` 29, one
continuous AES-128-CBC stream per inner file with the salt repeated in
every volume's header, `pack_size = align16(unpacked)` at the very end
only, and a file header whose CRC32 is of the PLAINTEXT on the final
fragment.
