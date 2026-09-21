# RAR 1.5 fixtures from a genuine DOS RAR 1.55

`dir_nested_155_m0.rar` (668 bytes, CRC32 `0x7f3c749a`) is the first 668
bytes of an archive written by DOS RAR 1.55 (Aug 1995) under dosbox, `a -r
-y -m0`, over a tree holding `SUB\NESTED\DEEP.TXT` (520 bytes, `nested
file\r\n` forty times). It is cut at the block boundary after the third
file header's data; a RAR 1.5 archive carries no end block, so the prefix
is a complete archive, and reference `unrar` 7.23 tests it `All OK`. Every
byte in it is the writer's own.

What it pins: the two directory headers carry header flags `0x8000` only,
unpack version 15, host OS 0 (MS-DOS) and attribute `0x10`. There are no
directory window bits, so the DOS directory attribute is the ONLY thing
marking `SUB` and `SUB\NESTED` as directories. Before this fixture the
reader tested the flags alone and extracted `SUB` as an empty file.

The writer was the 1995 DOS self-extractor `RAR155.EXE` (SHA-256
`ec48bfd97a609379a91069f6a2093fe4016875bb451499c53bd244e65d4102cc`), run
only inside dosbox in a container with no network. The binary itself is
not committed anywhere.
