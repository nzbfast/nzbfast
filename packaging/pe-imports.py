#!/usr/bin/env python3
"""pe-imports.py - read a Windows PE's IMPORT TABLE, and refuse a build
that needs the mingw runtime DLLs beside it.

    packaging/pe-imports.py --list  <file>     names, one per line
    packaging/pe-imports.py --check <file>...  exit 1 if any imports mingw
    packaging/pe-imports.py --selftest

WHY THIS IS NOT A `strings` GREP, which is the whole reason the file
exists. The obvious cheap version - `strings nzbfast.exe | grep -i
libgcc` - reports a CORRECTLY STATIC binary as broken, and that was
measured rather than reasoned about (26 Aug 2026, mingw-w64 14.0.0 /
gcc 16.1.0, x86_64-w64-mingw32). Every static mingw binary carries its
own build's DWARF paths, so `strings` on a `-static` C program returns:

    ../../../libgcc/libgcc2.c
    ../../../libgcc/config/i386/cygwin.S
    GNU C23 16.1.0 ... -fbuilding-libgcc ...

and a static C++ one adds `../../../../../libstdc++-v3/src/c++11/...`.
Those are the names of the source files libgcc and libstdc++ were BUILT
from, compiled INTO the binary precisely because it is static. A grep
that fires on them is red on exactly the builds it is supposed to pass,
and a gate that cries wolf is one people learn to wave through - the
same argument packaging/scan-release-assets.sh's own header makes about
its bare-name patterns hitting DEFLATE entropy.

The import table has no such ambiguity: a name in it is a DLL the
loader WILL go looking for at process start, and a name absent from it
is one the binary does not need. That is the actual question - "will
this refuse to start on a machine with no mingw" - rather than a proxy
for it.

WHAT IT REFUSES, measured on that same toolchain by building each arm
both ways and diffing the import tables:

    libwinpthread-1.dll   C code using pthreads, linked without -static
    libgcc_s_seh-1.dll    unwinding; the suffix is the unwind ABI, so
                          it is _dw2- on 32-bit and _sjlj- on old
                          toolchains - matched by prefix, not by the
                          one spelling this box happens to produce
    libstdc++-6.dll       any C++ in the link, without -static

Adding `-static` removed all three, in every arm. `libssp-0.dll`
(stack-protector) and `libatomic-1.dll` are the other two runtime DLLs
a mingw toolchain can hand you; neither appeared in any arm here, and
both are in the list because their absence today is a fact about our
current dependency set, not a property of the linker.

WHAT A CLEAN ANSWER IS WORTH, stated rather than overclaimed: the
import table is what the LOADER reads, so this cannot see a DLL a
program resolves for itself at run time with LoadLibrary, and it does
not judge the delay-import directory. Neither is how a mingw runtime
dependency arrives - the linker writes those into the normal import
directory, which is what is read here.

FAILING TO READ IS FAILING. A file that is not a PE is reported as such
and is not a pass (the caller decides; the scanner skips non-PEs and
checks every PE it finds). A file that IS a PE and cannot be parsed -
a truncated header, a section table that does not cover the import
directory, a name that runs off the end of the file - exits 3 and says
why. It must never come back "no mingw imports" because the parse gave
up, which is the one failure mode this repo's gate list keeps growing
to refuse: a matcher that has quietly stopped matching reads as a clean
tree forever.
"""

import sys

# The runtime DLLs a mingw link can leave behind. Matched
# case-insensitively (the import table's spelling is the linker's, and
# Windows itself is case-insensitive here) and by PREFIX, so the unwind
# ABI suffix on libgcc_s and a future soname bump on the others are
# covered without a second entry each. Every one of these is a file the
# user would have to have beside the .exe for it to start at all.
MINGW_RUNTIME_PREFIXES = (
    "libgcc_s",        # unwinding: _seh-1 / _dw2-1 / _sjlj-1
    "libwinpthread",   # pthreads
    "libstdc++",       # C++ runtime
    "libssp",          # stack protector
    "libatomic",       # libatomic
)


class NotPE(Exception):
    """The file is not a PE image at all."""


class BadPE(Exception):
    """It IS a PE and could not be read. Never a pass."""


def _u16(b, off):
    if off + 2 > len(b):
        raise BadPE(f"truncated at offset {off} reading a 16-bit field")
    return int.from_bytes(b[off:off + 2], "little")


def _u32(b, off):
    if off + 4 > len(b):
        raise BadPE(f"truncated at offset {off} reading a 32-bit field")
    return int.from_bytes(b[off:off + 4], "little")


def imported_dlls(data):
    """Every DLL name in the PE import directory, in file order.

    Raises NotPE if it is not a PE image, BadPE if it is one and the
    import directory cannot be walked. An empty list means the import
    directory is genuinely empty, which is a real answer.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        raise NotPE("no MZ signature")
    pe_off = _u32(data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        raise NotPE("no PE signature where e_lfanew points")

    coff = pe_off + 4
    n_sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    if opt_size == 0:
        raise BadPE("optional header is zero-sized, so there are no data "
                    "directories and the import table cannot be located")

    magic = _u16(data, opt)
    if magic == 0x20B:      # PE32+
        dirs_off = opt + 112
    elif magic == 0x10B:    # PE32
        dirs_off = opt + 96
    else:
        raise BadPE(f"unknown optional header magic 0x{magic:x}")

    n_dirs = _u32(data, dirs_off - 4)
    if n_dirs < 2:
        # Directory 1 is the import table. A PE that declares fewer
        # than two directories has no import table to read, which is a
        # real answer and not a failure.
        return []
    import_rva = _u32(data, dirs_off + 8)
    if import_rva == 0:
        return []

    # Section table follows the optional header; it is what turns an
    # RVA into a file offset.
    sections = []
    sec_off = opt + opt_size
    for i in range(n_sections):
        s = sec_off + i * 40
        if s + 40 > len(data):
            raise BadPE(f"section header {i} runs past the end of the file")
        va = _u32(data, s + 12)
        vsize = _u32(data, s + 8)
        raw_size = _u32(data, s + 16)
        raw_ptr = _u32(data, s + 20)
        # A section's virtual size may exceed what is on disk (bss-like
        # tails). Map only the part that is really in the file.
        sections.append((va, max(vsize, raw_size), raw_ptr, raw_size))

    def to_off(rva):
        for va, vsize, raw_ptr, raw_size in sections:
            if va <= rva < va + vsize:
                delta = rva - va
                if delta >= raw_size:
                    raise BadPE(f"RVA 0x{rva:x} falls in a section's "
                                "virtual tail with no bytes on disk")
                return raw_ptr + delta
        raise BadPE(f"RVA 0x{rva:x} is not covered by any section")

    def asciiz(off):
        end = data.find(b"\0", off)
        if end == -1:
            raise BadPE(f"unterminated name string at offset {off}")
        return data[off:end].decode("ascii", "replace")

    names = []
    desc = to_off(import_rva)
    # Import descriptors are 20 bytes each, terminated by an all-zero
    # one. The cap is a runaway guard: a corrupt table that never
    # terminates must fail, not spin.
    for _ in range(4096):
        if desc + 20 > len(data):
            raise BadPE("import descriptor table runs past the end of "
                        "the file with no null terminator")
        if data[desc:desc + 20] == b"\0" * 20:
            return names
        name_rva = _u32(data, desc + 12)
        if name_rva:
            names.append(asciiz(to_off(name_rva)))
        desc += 20
    raise BadPE("import descriptor table has no null terminator within "
                "4096 entries")


def mingw_imports(names):
    """The subset of `names` that is a mingw runtime DLL."""
    return [n for n in names
            if n.lower().startswith(MINGW_RUNTIME_PREFIXES)]


def _check_file(path):
    """Returns (verdict, detail). verdict is ok | mingw | notpe | bad."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return "bad", f"cannot read: {e}"
    try:
        names = imported_dlls(data)
    except NotPE as e:
        return "notpe", str(e)
    except BadPE as e:
        return "bad", str(e)
    bad = mingw_imports(names)
    if bad:
        return "mingw", ", ".join(sorted(set(bad)))
    return "ok", f"{len(names)} imports, none from the mingw runtime"


# --------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------

def _build_pe(imports, magic=0x20B, n_dirs=16, truncate_names=False):
    """A minimal but structurally real PE carrying `imports`.

    Built by hand rather than checked in as a fixture binary so the
    selftest runs on any box: the REAL both-ways proof is in
    packaging/tests/scan-release-assets-patterns.sh, which builds an
    actual mingw binary when a mingw toolchain is present.
    """
    sec_va = 0x1000
    sec_raw = 0x400
    # Lay out, inside the one section: the descriptor table, then the
    # name strings after it.
    desc_len = (len(imports) + 1) * 20
    blob = bytearray()
    name_rvas = []
    cursor = desc_len
    for name in imports:
        name_rvas.append(sec_va + cursor)
        cursor += len(name) + 1
    for i, name in enumerate(imports):
        d = bytearray(20)
        d[12:16] = (name_rvas[i]).to_bytes(4, "little")
        blob += d
    blob += bytes(20)                      # null terminator descriptor
    for name in imports:
        blob += name.encode() + (b"" if truncate_names else b"\0")

    opt_size = 240 if magic == 0x20B else 224
    pe_off = 0x80
    hdr = bytearray(sec_raw)
    hdr[0:2] = b"MZ"
    hdr[0x3C:0x40] = pe_off.to_bytes(4, "little")
    hdr[pe_off:pe_off + 4] = b"PE\0\0"
    coff = pe_off + 4
    hdr[coff + 2:coff + 4] = (1).to_bytes(2, "little")        # 1 section
    hdr[coff + 16:coff + 18] = opt_size.to_bytes(2, "little")
    opt = coff + 20
    hdr[opt:opt + 2] = magic.to_bytes(2, "little")
    dirs_off = opt + (112 if magic == 0x20B else 96)
    hdr[dirs_off - 4:dirs_off] = n_dirs.to_bytes(4, "little")
    hdr[dirs_off + 8:dirs_off + 12] = sec_va.to_bytes(4, "little")
    hdr[dirs_off + 12:dirs_off + 16] = len(blob).to_bytes(4, "little")
    sec = opt + opt_size
    hdr[sec:sec + 8] = b".rdata\0\0"
    hdr[sec + 8:sec + 12] = len(blob).to_bytes(4, "little")    # vsize
    hdr[sec + 12:sec + 16] = sec_va.to_bytes(4, "little")      # va
    hdr[sec + 16:sec + 20] = len(blob).to_bytes(4, "little")   # raw size
    hdr[sec + 20:sec + 24] = sec_raw.to_bytes(4, "little")     # raw ptr
    return bytes(hdr) + bytes(blob)


def _selftest():
    cases = 0
    fails = []

    def check(label, cond):
        nonlocal cases
        cases += 1
        if not cond:
            fails.append(label)

    clean = ["KERNEL32.dll", "api-ms-win-crt-heap-l1-1-0.dll", "ntdll.dll"]
    check("a clean PE32+ parses to its names",
          imported_dlls(_build_pe(clean)) == clean)
    check("a clean PE32+ has no mingw imports",
          mingw_imports(imported_dlls(_build_pe(clean))) == [])
    check("a clean PE32 (0x10b) parses too",
          imported_dlls(_build_pe(clean, magic=0x10B)) == clean)

    # Each banned name, on its own, must be caught.
    for name in ("libwinpthread-1.dll", "libgcc_s_seh-1.dll",
                 "libgcc_s_dw2-1.dll", "libgcc_s_sjlj-1.dll",
                 "libstdc++-6.dll", "libssp-0.dll", "libatomic-1.dll"):
        check(f"{name} is refused",
              mingw_imports(imported_dlls(_build_pe(clean + [name]))) == [name])
    # And its case-folded spelling, since the table carries the
    # linker's spelling and Windows does not care.
    check("an upper-case spelling is still refused",
          mingw_imports(imported_dlls(_build_pe(["LIBWINPTHREAD-1.DLL"])))
          == ["LIBWINPTHREAD-1.DLL"])
    # The measured false-positive shape: the DWARF source paths every
    # STATIC mingw binary carries. They are not imports, so they must
    # not be found by a reader that only looks at the import table.
    check("a static binary's libgcc DWARF paths are not imports",
          mingw_imports(imported_dlls(_build_pe(
              clean + ["../../../libgcc/libgcc2.c"]))) == [])

    # Not-a-PE is its own verdict, never a pass and never a failure.
    for blob, label in ((b"", "empty file"),
                        (b"not an executable at all", "plain text"),
                        (b"MZ" + b"\0" * 200, "MZ with no PE header")):
        try:
            imported_dlls(blob)
            check(f"{label} is NotPE", False)
        except NotPE:
            check(f"{label} is NotPE", True)
        except BadPE:
            check(f"{label} is NotPE", False)

    # A PE that cannot be read must FAIL, not report clean.
    good = _build_pe(clean)
    for mutate, label in (
        (lambda b: b[:len(b) - 40], "truncated import table"),
        (lambda b: b[:0x3C] + (0xFFFF00).to_bytes(4, "little") + b[0x40:],
         "e_lfanew past the end"),
        (lambda b: _build_pe(clean, truncate_names=True),
         "unterminated name string"),
        (lambda b: _build_pe(clean, magic=0x1234), "unknown magic"),
    ):
        try:
            imported_dlls(mutate(good))
            check(f"{label} fails closed", False)
        except BadPE:
            check(f"{label} fails closed", True)
        except NotPE:
            # e_lfanew pointing off the end is legitimately "not a PE":
            # there is no PE signature there to find.
            check(f"{label} fails closed", label == "e_lfanew past the end")

    # A PE declaring fewer than two data directories has no import
    # table, which is a real empty answer rather than a parse failure.
    check("n_dirs < 2 is an empty answer, not a failure",
          imported_dlls(_build_pe(clean, n_dirs=1)) == [])

    # The roster itself: a shortened ban list must not still pass the
    # names it dropped. Pins the list against being quietly narrowed.
    check("the ban roster covers all five families",
          len(MINGW_RUNTIME_PREFIXES) == 5)

    print(f"pe-imports selftest: {cases} cases, {len(fails)} failed")
    for f in fails:
        print(f"  FAIL: {f}")
    return 1 if fails else 0


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    mode = argv[1]
    if mode == "--selftest":
        return _selftest()
    files = argv[2:]
    if not files:
        print(f"{mode}: no files given", file=sys.stderr)
        return 2

    if mode == "--list":
        for path in files:
            verdict, detail = _check_file(path)
            if verdict == "bad":
                print(f"{path}: UNREADABLE PE: {detail}", file=sys.stderr)
                return 3
            if verdict == "notpe":
                print(f"{path}: not a PE ({detail})", file=sys.stderr)
                return 2
            with open(path, "rb") as fh:
                for n in imported_dlls(fh.read()):
                    print(n)
        return 0

    if mode == "--check":
        rc = 0
        for path in files:
            verdict, detail = _check_file(path)
            if verdict == "mingw":
                print(f"{path}: imports the mingw runtime: {detail}",
                      file=sys.stderr)
                rc = 1
            elif verdict == "bad":
                print(f"{path}: UNREADABLE PE: {detail}", file=sys.stderr)
                rc = 3
        return rc

    print(f"unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
