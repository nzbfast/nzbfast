# The layout catalog

Every file in this directory is one **layout profile**: a TOML document
describing one way a post can be laid out on Usenet, and the end state
a client must reach from it. A profile is data, not code. Adding a
layout to this repo's coverage means adding a file here; it does not
mean adding a case to a test table, and it never means adding a branch
to the generator.

The round-trip oracle generates one test per file in this directory.
For each profile it builds the layout (deterministically, from the
profile's own seed), serves it from a mock server, runs the real
`nzbfast` binary against the NZB, and asserts the client ends with the
declared files, byte for byte and name for name. So a failure names the
profile that failed, and a single layout can be re-run on its own.

The schema is `crates/postfast/src/profile.rs`, which is the
authoritative reference for every key and value. This file is the
house rules for writing one.

## Where coverage status lives

**Nothing in this directory, and nothing in the spec, says which layout
shapes the client handles.** Section 7 of
`research/SPEC-POSTING-LAYOUT-TOOLKIT-2026-09-03.md` lists seven planes
of numbered IDs, and those tables are VOCABULARY: they carry no status
column and no platform column on purpose, because an earlier draft typed
one and was wrong in both directions.

Status is derived, by `tools/layout-coverage.py`, from the profiles here
and the oracle's junit:

```sh
cargo nextest run --profile ci -p nzbfast --test integration -E 'test(/^layouts::/)'
tools/layout-coverage.py --junit target/nextest --platform macos
```

Every plane reads one of four letters. **R** recognised: a profile
selects it, passes, and is not a declared gap. **K** contemplated:
profiles select it and not one of them both passes and is free of an
`[expect] gap`, so a green test over today's wrong answer never reads as
a working client. **U** unselected: nothing here selects it, which is
usually a profile nobody has written yet and is exactly what the report
is for. **-** the oracle has not run on that platform.

Two consequences for writing a profile. The report derives a plane
selection from the profile's VALUES, so a row exercises a plane by
selecting it and not by being named after it. And a plane that reads U
is fixed by writing a profile, never by widening the report's predicate
until an existing row falls into it - that would move a number without
moving any coverage. The predicates and the argument for each one are in
the script's header.

## The neutral defaults

**Every plane table is optional, and leaving one out selects the
neutral row.** A profile therefore states only what it varies, and the
whole difference between a layout and the plain case is visible by
reading the file. The neutral selection is:

| Table | Neutral | Meaning |
|---|---|---|
| `[naming]` | N1 | descriptive name in `name=` and in the subject, natural part order, UTF-8 |
| `[container]` | C0 | no archive: the payload files are posted as they are |
| `[recovery]` | P0 | no PAR2 set |
| `[encoding]` | defaults | 128-byte lines, 768,000-byte articles, part CRC present, declared size true, `=ypart` present, nothing after `=yend` |
| `[nzb]` | faithful | the map agrees with the wire in every particular: real name meta, real subjects, real sizes, every posted segment listed, the articles' own date |
| `[fault]` | none | no damage baked into the emitted bytes |
| `[serve]` | none | the mock server answers every article correctly |

`n1-c0-p0-baseline.toml` is that row written out, and it is the control
arm for the catalog: a failure anywhere else means little until the
baseline passes.

**A typo is a load error, not a silent neutral.** Every table refuses
unknown keys, so `redundancy_pc = 10` fails by name rather than quietly
leaving the profile at P0. This is the property the whole toolkit is
built on: a profile that passes because the plane it meant to select
was never selected would be worse than no profile at all.

## The seed, and why nothing here is random

`[layout] seed` is the only source of randomness in a run. Opaque
names, message-ids, generated payload bytes and the choice of which
articles a fault lands on all come from it, through one seeded
generator. The same profile with the same seed produces a
byte-identical layout on every machine and every run, so a failing
oracle run reproduces from the profile alone.

Nothing in the generator draws from the operating system's entropy. If
a layout you want needs a random choice that does not yet exist, it is
drawn from the seed like every other one.

## `[expect]`, and the one way to pin a known gap

The generator derives `[expect]` from the source and the planes: with
no override, a profile asserts that the client ends up with every
source file, under its real name, byte for byte.

**Overriding `[expect]` is the ONLY way to pin behaviour that is not
yet right, and an override without `gap` is not allowed to stand.**
Write what today's behaviour is, say in `gap` why it is not the right
behaviour, and list in `arrives` which source files the client DOES
end with:

```toml
[expect]
complete = false
arrives = ["movie.mkv"]
gap = "the sample is filed under its token, because nothing out of band carries its real name"
```

The three go together and the schema refuses any two without the
third. `arrives` names the file under the name the LAYOUT carries for
it, which under an opaque or FileDesc-named row is not the `[source]`
spelling; an entry that names nothing the layout carries is refused
with the list that would have been right. An empty `arrives` beside
`complete = false` is legal and means the client ends with none of the
payload, which is what an unrepairable row looks like.

**A run's EXIT CODE is a requirement too, in both directions**, and
`exits` is how a row pins the one shape `complete` cannot describe: a
job that produced every file correctly, under the right names, and
reported failure anyway. Unset, the expected exit follows `complete` -
a run that delivers everything exits zero, a run that cannot says so -
so writing `exits` is always pinning a gap and always needs `gap` text:

```toml
[expect]
exits = "nonzero"
gap = "the damage is repaired and the payload extracted correctly, and the run still exits non-zero"
```

A gap row is graded differently, and knowing how is what keeps one
honest. Every name in `arrives` must be there and byte-exact, and
every OTHER payload name must be absent - so the day the engine
handles the layout, the row goes red and somebody reads the `gap` text
and deletes the override. What is not graded is the engine's own
bookkeeping: a run that does not finish leaves a journal so a retry
resumes and renames an unverified payload aside so nothing imports it,
and those spellings are the client's answer rather than anything a
profile asked for.

The coverage report lists the profile under that text and counts the
planes it selects as contemplated rather than recognised. That is what
keeps "we handle this" and "we have a test that agrees with what we do
today" apart. A profile that asserts today's wrong answer with no `gap`
is a rubber stamp: it turns a defect into a requirement, and the next
lane that fixes the defect gets a red test and no idea why.

## Nothing real in a profile, ever

This crate ships in the public export. Profiles are read by strangers
and are committed for as long as the repo exists.

- **Groups:** `alt.test` and `alt.binaries.test` only. No real binary
  group, and no group name taken from a real post.
- **Hosts and accounts:** none. Not a provider hostname, not a
  username, not an API key, not a machine name. The oracle runs against
  a mock server on loopback, and there is nothing for a real host name
  to mean here.
- **Payload:** generated from the seed. No copied file, no real release
  name, no name lifted from a real post. A profile is self-contained;
  the catalog carries no binaries.
- **Passwords:** `[container] password` is furniture for an encrypted
  layout. Use something obviously fake. Never a password used anywhere.

A profile that needs a real-world name to be meaningful is describing
its `note` field, not its layout.

## `[recovery]`, and what it does to the expectation

The recovery plane is the one plane that changes what the client must
END with rather than only what goes on the wire. A PAR2 set's FileDesc
packets carry each member's RELATIVE PATH, and in a no-container post
nothing else carries a directory at all - so a member a set covers is
expected under its `[source]` name, directories and all, while an
uncovered member keeps the name the wire gave it. One post can hold
both, which is what `covers` is for.

Three things about writing a recovery profile that are not guessable
from the schema:

- **`zero_byte_member = true` means the 0-byte `[source]` files are
  DESCRIBED and never posted.** An empty file has no bytes to put on a
  wire, so its FileDesc packet is the only record it exists (the
  VIDEO_TS placeholder). Without the flag, a 0-byte source is the other
  real shape: one lone `=ybegin size=0` article. Two shapes, one
  selection, and the profile says which by the flag rather than by the
  size.
- **`names = "filedesc-only"` requires `[naming] wire = "opaque"`.** P3
  says the set is the ONLY place a real name exists; a descriptive wire
  beside it would quietly make the profile a P1 row that happened to
  pass. The recovery files themselves are still announced under their
  own names, deliberately: a client that cannot find the set has
  nothing at all, and whether packets can be found without an extension
  is P2's question and P10's.
- **`hostile_names` may only carry names whose end state is a
  requirement.** Entries are positional over the covered members and
  are patched into every file of the set. A traversal attempt, a
  duplicate, a name whose containment answer differs by platform - each
  is refused by name, because the oracle grades an exact output tree
  and the right answer for those is whatever the sanitizer does, which
  would be a screenshot rather than a requirement. Those shapes are
  pinned in `crates/nzbfast/tests/e2e_norar/pins.rs`. A patched name
  must also FIT the region the creator's own name occupied, so give the
  member a long enough name in `[source]`; the refusal prints both
  numbers.

**`[source] same_as` (P12) is the dedupe shape**: the entry's bytes ARE
the named earlier file's bytes, the set describes both members, and only
one of them is posted. A PAR2 file id is hashed over the name as well as
the content, so the two descriptors are distinct and agree about
everything else, and the client has to write the second file from the
first rather than fetch it. Both names must land byte-exact: reporting
the second missing fails a post that is complete.

It shares P5's described-and-never-posted mechanism and states a
different requirement, so keep the two apart when you write a row. A P5
placeholder is empty and materialising it costs nothing; a dedupe copy
is the full length of a file that arrives exactly once. The schema
refuses a `same_as` that does not resolve backwards to a plain earlier
entry of the same length, one beside a `zero_head`, and one beside a
container, and the generator refuses a copy no set covers.

**`[recovery] outer = true` (P13) builds THE CHAIN**: a second set whose
members are the first set's own `.par2` files. With `names = "opaque"`
(which it requires, and the schema refuses anything else) the payload
rides under a token and so does its recovery set, so nothing announced
in the post describes the payload at all - and a small outer set under
ordinary `.par2` names describes the inner set. A name-driven client
walks outer, inner, payload; a client that recognises PAR2 packets by
content skips the whole thing. Both must reach the same file.

An outer set changes what the INNER set is, and the expectation follows
that rather than the ordinary recovery rules. The inner files are the
outer set's payload, so they land under their real `.par2` names (the
outer set describes them, so the post carries those names), they are not
swept (a named `.par2` is announced furniture, and the sweep takes
token-named packets), and every one of them arrives including the parity
volumes - a volume is eager-skipped when it is parity for the PAYLOAD,
and these are the outer set's own members.

An outer set beside `hostile_names` is refused: that patch rewrites
FileDesc packets in the inner files after the outer set was cut over
them, so the outer set would report the whole inner set damaged.

**`[recovery] phantom_covers` (P11) builds a FOREIGN set**: a complete,
sealed recovery set of its own, covering members that are named, sized
and never posted. It is the poisoned or misfiled set that turns up when
somebody uploads one release's `.par2` files beside another release's
articles, and the requirement it states is a negative one - the job must
not fail, and nothing may appear on disk under a name only the foreign
descriptors mention.

Do not confuse it with `zero_byte_member`, which is also described and
unposted. A P5 placeholder is a member of the REAL set with no bytes, so
materialising it is correct and a row asserts it happens; a phantom has
bytes the post never carried, so materialising anything under its name
is a defect. The schema refuses a 0-byte phantom and a phantom that
names a `[source]` file, so neither shape can be written into the other
by accident.

**`[recovery] decoy` (P10) is the file that is NOT a set**: a name the
post spells `.par2` over bytes no client can verify anything against.
Every other row in this plane asks what a client does with a set; this
one asks how it decides that something IS one, and the answer has to
come from the packets because the suffix is the poster's free choice.

What the bytes are is not a selection - `crate::recovery`'s
`create_decoy` argues the shape - and it matters that they are not
noise. A decoy of random bytes is turned away by the first magic check,
so a client with no packet reader at all passes that row. The emitted
decoy carries a genuine Main packet and a genuine Creator packet cut
from a real creator's index, then a framing-valid cell whose seal is
junk, then junk: it clears the extension, the magic, the framing walk
and the seal check, and fails only on the last rung, because the set it
declares has no FileDesc packet and so names no member.

A decoy ARRIVES, and that is the row's discriminator rather than a
detail of it. It is not parity, so nothing eager-skips it; it is
announced under its own name, so the sweep (which takes packet-shaped
bytes under a TOKEN) never looks at it; and it is not a set, so no
verify spends it. A client that believed the extension would have left
it out of the tree, and that is where the belief shows.

The two rows are a pair and neither is complete alone. With the real
set ANNOUNCED the client is right (`p3-p10-decoy-beside-an-announced-
set`); with the real set token-named, so that the decoy is the only
`.par2` in the post, it is not, and
`n2-p2-p10-par2-named-decoy` is the gap row that pins it.

**What lands, and what does not.** The `.par2` INDEX is part of the
expected output tree and the parity volumes are not: a clean run
fetches the manifest it verifies against and skips parity until
something needs repairing, and `nzbfast get` does not sweep usenet
furniture (that is the daemon's filing step). Both halves are
requirements - a client that pulled every volume on a clean download
would be spending the user's bandwidth on parity it never used.

## A row that has to REPAIR carries no spare parity

Two selections make the client unable to reach the payload without the
recovery set: `[encoding] part_crc = "wrong"`, which poisons one
article so its blocks go missing, and `[nzb] drop_segments_pct`, which
leaves posted articles out of the map so the client has no id to ask
for. A run like that fetches parity volumes, writes them beside the
payload and does not sweep them, so the volumes ARE part of the end
state - unlike a clean run, where the index arrives and the volumes do
not.

Which volumes a repair pulls is a client policy where there is a
choice: it fetches whole volumes and picks among them, and a profile
that named a particular set of volume files would be pinning that
policy by accident and would go red the day it improved. So give such a
profile **exactly as much parity as the repair consumes** - work out
how many PAR2 blocks the lost articles cover, set `redundancy_pct` to
produce that many recovery blocks, and say the arithmetic in the note.
With no margin, "every volume arrives" is forced: N blocks cannot be
rebuilt from fewer than N recovery blocks.

`expects_repair` in `crates/postfast/src/layout.rs` is the one place
that list of selections lives, and the fault and serve planes belong in
it rather than in a second rule beside it.

## What `[expect]` cannot say yet

The expectation is DERIVED: the output tree is the source list under
the names the layout carries, and a profile can override only
`complete` and `gap`. So an end state that is neither "every source
file" nor "every source file, and the job also failed" cannot be
declared at all - a payload the client truncated to a length the post
declared, or a `.nzbfast-partial` beside a `.nzbfast.journal` where the
client correctly refused to finish. Both are real, correct-or-arguable
client behaviours, both are reachable from `[encoding] declared_size`,
and `e4-declared-total-long` records what each one does in its note
rather than leaving the next author to rediscover it.

`complete = false` is also ONE-SIDED today: it means success is not
required, not that failure is required. A row that wants to pin "this
must not complete" needs a third state on that field, which is the
oracle's to grow.

## Writing one

1. Name the file after the planes it selects, lowest ID first, so a
   directory listing reads as a coverage map: `n2-c2-p2-opaque-split`.
2. `[layout] note` says which matrix row, handoff or incident the
   profile pins. A reader deciding whether deleting it loses anything
   reads that field and nothing else.
3. State only what you vary. If a key equals the neutral value, delete
   the key; a profile full of restated defaults hides its own point.
4. Keep the payload as small as the shape allows. Every profile is a
   test that runs on every push; bytes here are wall time there.

## `[container]`, and the three archive formats

`kind` names the FORMAT and the storage mode together - `rar-stored`,
`rar-compressed`, `7z-stored`, `7z-compressed`, `zip-stored`,
`zip-compressed` - so C1, C2 and C3 are the mode and C12 is the format.
A stored 7z or zip selects C1 (or C2 when it is split) and C12 both.

Three keys on that table are RAR's alone, and a 7z or zip profile that
writes one is refused by name rather than having it quietly dropped:

- **`version`** names a RAR generation.
- **`recovery_record_pct`** (C10) is RAR's own in-archive recovery
  record; neither other format has an equivalent, so there is no writer
  to grow. Protect the post with a `[recovery]` set instead.
- **`volume_style`** (C11) spells an ordering into volume names. A
  split 7z has one spelling, `<name>.7z.001`, `.002`, ..., and a split
  zip one spelling of its own, `<name>.zip.001`, `.002`, ...

**A split 7z, and a byte-split zip, are not sets of volumes.** Each is
the finished archive cut into fixed-size pieces, and only part one
carries a signature - concatenating them gives the archive back byte
for byte, which is how the client reads one
(`nzbkit::zip::Parts` opens the ordered files as a single logical byte
space, and the 7z path does the same). Two things follow.
`volume_bytes` means bytes of ARCHIVE per part on those two kinds and
payload bytes per volume on a rar one, which is the format's difference
rather than the generator's; and `volume_names = "opaque"` beside
either is refused, because C6's premise is that the ordering comes from
the CONTENT and a part past the first has no header, no index and
nothing to sort on. A zip is worse off still - its central directory
sits at the END, so part one carries an index of nothing.

**The zip format's OTHER multi-part spelling is not emitted.** WinZip
spanning - `.z01`, `.z02`, ... with the trailing `.zip` holding the
central directory and therefore sorting LAST - is a grammar rather than
a style, needing a spanning marker and per-entry disk numbers the
writer does not emit. `nzbkit::zip` reads it; nothing here writes one,
and no key selects it, because a key nobody can select is worse than
none. The `volume_style` refusal names it, which is where an author
asking for a different volume spelling would look.

**C9, a launcher stub, works on all three formats.** `wrap` never emits
a set it has not read back, and it steps over the stub by the length it
wrote rather than leaning on a reader to scan past it - which only
`rars` does, and which was never the property a C9 row proves.

**C3 has two arms and they answer different halves.** The RAR writers
fall back to STORE per entry whenever compression would not shrink it,
silently, so a `rar-compressed` row over neutral bytes would be a
stored archive wearing a C3 label - which the generator still refuses
by name. It needs `[source] content = "compressible"` beside it, and
then the writer really compresses; that is the arm about a writer that
shrank. The 7z writer records one content method for the whole archive
and never falls back, so an LZMA2 archive over incompressible bytes is
still one the client must run the decoder over, and it comes out BIGGER
than its payload - the honest cost of the shape, and the arm about a
decoder the client must RUN. The zip writer behaves the same way, per
ENTRY rather than per archive, so `zip-compressed` is a third row of
the second kind and a writer that stored one member of several is
caught as a partial C3. All three are worth having.

**Encryption is a rar and a 7z `kind`, and not a zip one.** It was
refused on 7z by name for one day in a way that reads like a format
rule, and it never was one. `encryption = "data"` and `= "header"` both
reach the 7z writer since 4 Sep 2026: the AES coder goes in front of the
content method, and `set_encrypt_header` decides whether the end header
is sealed with it. Before that the writer was handed no password at all,
so it emitted an archive that opened for anyone while the profile
claimed C4 - which is why the refusal existed and why the rows that
lifted it assert the archive does NOT open unpassworded.
`c4-encrypted-7z-data` and `c5-encrypted-7z-header` are the pair, and
`c4-c13-password-chain-7z-inner` puts a 7z at the inner level of a
password chain, which is the one shape the client's own 7z password
probe had nothing pointing at.

ZIP is still refused by name, and it is a writer gap rather than a
format one: `nzbkit::zip` reads both zip schemes, and the writer's crate
gates the AE arm behind a feature that draws the key salt from
`getrandom` with no seeded alternative. That is the same reproducibility
problem `rars::Entropy` solved for RAR and
`vendor/sevenz-rust2/src/write_entropy.rs` then solved for 7z, so the
shape of the fix is known; it is the third crate that has not had it.

**`[container] polyglot` (C8) puts BOTH formats in one file**: a second,
complete archive of the other format appended behind the selected one,
so the emitted bytes are structurally valid twice over and what the
client does depends on which signature it trusts and in what order.
Nothing here is malformed, which is what makes the plane a judgement:
both archives open.

It requires `leading_bytes` and refuses a second archive of its own
family, both for the same reason. `nzbkit::sfx::sfx_payload_at` is the
ONLY place in the engine that weighs two container signatures against
each other, it runs only behind a launcher stub, and it folds both RAR
signatures onto one family. A first signature at offset 0 is answered by
the routing sniff before a second candidate is looked for, and two
archives of one family are one candidate said twice.

The end state is that the client must produce what RUNNING the
self-extractor would produce, which is the EARLIEST confirmed archive;
`c8-polyglot-rar-then-7z` argues it at length. The short version is that
a later confirmed signature is far more often INSIDE the earlier archive
than a peer of it, which is C7 and C13, so a rule preferring the later
signature or a format would open a nested set at the wrong level.

The two rows are a pair and neither is worth much alone. A single
ordering is green both for a client taking the EARLIEST candidate and
for one that prefers the format that ordering happened to put first;
`c8-polyglot-7z-then-rar` is the mirror that separates them. Sensitivity
was measured rather than assumed: patching `sfx_payload_at` to take the
LAST confirmed match reds both rows and leaves the C9 row green.

The same missing zip writer is what keeps the sharpest pairing out. A
zip is located from its TAIL, so a RAR against a zip would give the
client two independent locators with no position to compare, and force a
real preference rule where these rows need only an ordering one.

### `[[container.inner]]`, a stack whose levels differ

`nested = N` says "N further levels, all like this one" and is what most
nested rows want. `[[container.inner]]` says what each level IS, and its
COUNT is the depth - so the two are the same number said twice and a
profile that writes both is refused by name.

The tables are read **outermost-inner first**: the level just below the
posted set, then the one below that, down to the archive that holds the
payload. That is the order a shape is named in - RAR over 7z over RAR
over the payload - and a profile that listed the chain backwards would
be one more thing to get wrong.

An inner level carries a `kind`, a `version` and a
`recovery_record_pct`, and nothing else. The volume split, the volume
naming and the SFX prefix belong to the OUTERMOST level, because that
is the set a poster puts on the wire, and an inner archive is one
member of the level above it and therefore unsplit; an inner table
naming `volume_bytes` is refused by name rather than accepted and
applied nowhere.

C7 is the depth and C13 is a stack whose levels DIFFER. Spelling out
three identical levels selects C7 in a longer way and is not C13,
because nothing about it exercises the changing shape.

### `siblings`, a file riding inside a level

`siblings = [{ name = "notes.txt", bytes = 90 }]` puts an extra file
inside a container level, beside the archive below it. It is what the
ladder legs of the nested corpus carry at every depth, and a client that
stopped denesting the moment a level held something besides an archive
would pass a sibling-free ladder and fail those legs - so the presence
is the row.

Four things about writing one:

- **It goes in AFTER the archive below it**, so a level's first member
  is still the archive. A fixture that put the sibling first would agree
  with a client that reads only the first member, which is the client
  the row exists to catch.
- **The list is per LEVEL.** `[container] siblings` is the outermost
  level's alone, `nested` or not, and a sibling at every level is
  written with a `[[container.inner]]` table apiece, each naming its
  own. Every level extracts into the SAME output directory, so one list
  repeated down a stack would put one name at every depth and all but
  one would be overwritten - the schema refuses two files that would
  land under one name, siblings and `[source]` files together.
- **A sibling has bytes.** A 0-byte one is `[recovery] zero_byte_member`'s
  shape, whose requirement is about a FileDesc packet rather than an
  archive entry, and it is refused by name so the two cannot be written
  into each other.
- **It is part of the expected tree, and it is not a payload name.**
  The end state is the payload first and then every level's siblings, so
  a complete row grades them exactly; a gap row's `arrives` names
  `[source]` files only, because a sibling is archive furniture the post
  carries rather than something the profile asked to be delivered.

### `recovery_pct` on a level, and damage under it

`[[container.inner]] recovery_pct = 30` cuts a PAR2 set over THAT
level's archive and packs it into the level above, beside the archive
it covers. Nothing in the NZB mentions it: the post is intact, the
posted set verifies, the outer unpack succeeds, and what comes out is
an archive with a recovery set sitting next to it. A client that treats
"the outer unpack succeeded" as the end of the job files two files and
reports success having delivered no payload.

`[fault] corrupt_payload` is what poisons the archive that set covers.
Write `inner_level = N` instead of `file`, where N counts the
`[[container.inner]]` tables in the order they are written - the same
numbering the stack is described in. It is the SAME key at two depths
rather than a second table: both are "spoil these bytes after the
recovery data that covers them was cut", and only the depth decides
which recovery data and therefore where the generator does it. An entry
naming both or neither is refused, and so is one pointing at the
outermost level, whose damage is `corrupt_headers` (F3) and
`truncate_last_volume_bytes` (F5).

Four things about writing one:

- **The span's bounds are checked at the ARCHIVE, not in the schema.**
  How long a level's archive is is the writer's answer, not the
  profile's, which is why a `[source]` span is refused at load and this
  one is refused at generation with the length that was measured.
- **Put the span well past the header** so the fault is a DATA fault
  the recovery data repairs. A span in the header region is F3's
  question wearing this key.
- **Recovery data at a level covers everything BELOW it**, because the
  levels below are members of the archive it protects. A stack with
  data at several depths is a ladder rather than independent answers,
  and the outermost usable rung does the work. `nc-a1-damage-at-every-level`
  measures which one.
- **A level's own set is not part of the end state.** It is spent by
  the repair it exists for, exactly as the posted parity volumes are;
  a `.par2` left in the output directory after a successful repair is a
  leftover. A sibling, by contrast, IS in the end state, because it is
  an ordinary file the post carries. Measured on the first `nc-r4` run,
  which was written the other way round.

## `[source] split`, volumes without an archive

`split = N` posts one payload file as N contiguous raw wire files -
`<name>.001`, `<name>.002`, ... - and the client is expected to land the
file JOINED, under its `[source]` name. No rar bytes, no unpack pass,
and the parts are spent the way an archive's volumes are: a part left in
the output tree is a client that stopped at the wire files.

`split_names` picks which side of the cut a recovery set describes, and
that single key is the whole difference between the plane's two rows:

- `"parts"` (K1): the set describes `<name>.001` and `<name>.002`. The
  client renames them from their descriptors and then has to JOIN what
  it named - the second step is the row, because the rename alone leaves
  two correctly-named files and a payload nobody can play.
- `"join"` (K2, the default): the set describes the whole file at its
  full length, and nothing in the post says the wire files are ranges of
  it. The client has to harvest the described member's blocks out of
  files that match no descriptor.

Three things about writing one:

- **A split profile carries exactly ONE `[source]` file**, refused by
  name otherwise. With a split the wire files and the source files are
  not one to one, and the end state of a mixed post - one member joined
  out of parts, another named by the wire - has no derivation the
  generator can state. Each of the legs this plane exists for is one
  logical file, which is what the shape is in the field.
- **Split and `[container]` are refused together.** Splitting an archive
  is C2's `volume_bytes`, and two answers to one question is not a row.
- **Block alignment is arithmetic you choose, not a rule.** Cut the file
  so each part is a whole number of `block_bytes` and every block of the
  join sits inside one part, which is what lets a block-harvesting
  client assemble it with no recovery spend. An unaligned cut is a
  harder row and a different one; say which you wrote in the note.

## `[companion]`, the sidecar plane

`[companion] sfv = true` posts an `.sfv` beside the payload, listing
every POSTED file's relative path against its CRC32. It protects nothing
and repairs no byte, so it is not a recovery selection - what it carries
is the half of a PAR2 set an obfuscated post actually depends on, the
names and the tree, for a few hundred bytes. A post may carry a sidecar
and a set at once.

Four things about writing one:

- **The sidecar is posted under its own name whatever `[naming] wire`
  says**, and `sfv_name` spells it (`post.sfv` by default). That is the
  plane's rule, not a convenience: the payload rides under tokens
  precisely because the sidecar says what everything is, so a
  token-named sidecar is a name source nothing can find. The client's
  own tier reads sidecars by CONTENT as well as by extension, which is a
  real field shape and a harder row - it needs a naming key this plane
  does not have yet.
- **A member the sidecar names lands under the relative path it
  spells**, directories and all, which is what makes it a tree carrier
  as well. Where a set also covers the member the SET wins, because its
  claim is an MD5 pair over bytes it can rebuild and the sidecar's is
  the poster's unverified word.
- **A member that is described and never posted gets no line.** A P5
  placeholder and a G5 dedupe copy are on no wire, so a checksum for
  them could be matched against nothing.
- **The sidecar is part of the expected tree.** It is text under an
  ordinary extension, not packet-shaped bytes under a token, so the
  leftover sweep that removes an opaque `.par2` never looks at it.

A sidecar beside a `[container]` is refused by name: the posted files
are volumes, a successful unpack spends them, and every line would name
a file that is correctly absent from the end state.

## The two fault planes, and why there are two

`[fault]` is damage baked into the bytes that get posted. `[serve]` is
damage the mock server does to its answers. The split is not
bookkeeping: a serve-time fault is a fact about one download, so
asking again or asking a second server fixes it, and a
generation-time fault is a fact about the post, which every client
that ever fetches it meets and only recovery data can answer. A row
that confuses the two proves the retry path while claiming to prove
the repair path.

**`[serve]` is a map onto `nzbkit::mock::Chaos` by field name, and
nothing in `postfast` implements a fault.** The mock is this repo's one
fault server, with about forty knobs and years of measured provider
behaviour behind them, and the whole e2e suite already drives it. If a
layout needs a fault Chaos cannot express, the fix is a knob in
`nzbkit::mock` with a test of its own - never a second mechanism here.

**Articles are chosen two ways, and both are reproducible.** A
percentage (`missing_pct`, `corrupt_pct`, ...) is drawn from the
profile's seed. A position list (`missing`, `corrupt`, `truncate`,
`stall`, `stall_pre`, `swap`, `slow_ttfb`) names articles outright:
0-based indices over the whole post in posting order, payload files in
`[source]` order and then the recovery files, each file's segments in
segment order. Write a percentage when the row is about a SHARE of the
post and a position when it is about a PARTICULAR article, and say
which in the note. A position past the end is a load error.

Three rules that are not guessable from the schema:

- **One article, one fault.** Named positions come out of the pool
  before percentages draw from it, so a plan asking for 2 % missing and
  2 % corrupt damages 4 % of the post and never asks the server to do
  two things to one article. A position named twice, in one list or
  across two, is refused.
- **A percentage that rounds to zero still takes one article.** Rows
  here are asked to keep their payloads small, so 2 % of twelve
  articles is 0.24, and a fault plan that damaged nothing would read
  like a test and be none.
- **The fault planes draw from their own streams.** A fault row is
  almost always a clean row with a table added, and the two are
  diffable: adding `[fault]` or `[serve]` moves no payload name and no
  payload message-id.

**What lands changes when the layout is damaged.** A clean run fetches
the `.par2` index and skips the parity volumes; a run that has to
repair fetches them, so they are part of the end state. An index that
is `damaged` or `absent` also puts them there, because the names have
to come out of them - and such a row must carry exactly ONE volume,
because a client that only needs a name reads volumes until it has one
and stops, and how many that is is its answer rather than a
requirement. The generator refuses the multi-volume shape by name.

**`[fault] corrupt_headers` and `truncate_last_volume_bytes` damage an
ARCHIVE**, so a profile that selects one without a `[container]` is
refused by name rather than having the damage applied to a payload file
that is not a volume. Both run AFTER the recovery set is cut, which is
the only order in which the set has anything to say: a set built over
already-damaged volumes would describe the damage, agree with it, and
ask the client to repair nothing.

**`[fault] corrupt_payload` (F8) is the one fault where what is POSTED
and what must LAND are different bytes.** It writes fault-stream bytes
over a named span of a payload file, after the recovery set was cut over
the clean ones, so the article that carries the span is well formed and
its yEnc part CRC is computed over the damage. No re-ask helps and no
second server helps; only the set's own block hashes can see it. That is
what makes it a different row from `[serve] corrupt`, which flips a byte
in the ENCODED article so the CRC fails and the client meets a refused
article whose missing range it already knows. Write the span into the
first 16 KiB when the row is about the head-hash tier having nothing to
claim, and past it when it is about detection alone.

Three things about writing one:

- **The file and the offset are the profile's, and the replacement
  bytes are the seed's.** Unlike F3, which cannot name a volume because
  the writer decides how many there are, a payload file's name and
  length are what `[source]` itself declares.
- **A span must land inside the file** (the schema refuses one that
  does not, and a zero-length one), and the member must be covered by a
  set. Damage no set covers is refused by name: the expectation the
  generator derives is the SOURCE bytes, and no client could reach them.
- **The row repairs**, so the parity volumes are part of the end state
  and the "no spare parity" rule below applies to it: count the blocks
  the span lands in and give the set exactly that many recovery blocks.

**`[source] content` says what a file's bytes LOOK like** past being the
right length, and `"noise"` - the neutral value - is the ordinary
all-stream file every other row is built over. Two arms, and they came
from one question asked from two directions in the corpus rounds:

- `"mpegts"` puts an MPEG transport stream's sync byte on every
  188-byte packet boundary and leaves the other 187 as drawn. The
  extensionless-payload shape: a post with no name source at all, over
  bytes a container sniffer has something real to recognise in. Without
  it such a row passes only because there was nothing to see. The
  schema refuses a file too short to carry four whole packets, because
  a lone sync byte selects the shape and emits no stride.
- `"compressible"` repeats each drawn byte for a drawn run of at most a
  couple of dozen, so an archiver has something to shrink. C3's RAR arm
  is unreachable without it: the RAR writers silently STORE a member
  they cannot shrink, and the generator refuses a compressed selection
  it answered by storing rather than emitting a C1 archive wearing a C3
  label. (C3's 7z arm needs none of it, for the reason the container
  section above gives, and asks a different question.)

**Neither is `periodic = true` returning by another name, and the
compressible arm is the one that had to prove it.** `periodic` is
refused because par2cmdline 0.8.1 miscounts identical recovery BLOCKS.
The MPEG arm rewrites one byte in 188, so two blocks are exactly as
unequal as in the neutral case and it is legal beside a set. The
compressible arm bounds every run far under any block, so no block it
makes can be constant - and it is refused beside a `[recovery]` set
that would actually COVER it, which is the half a reader can check from
the profile text: par2gen never sees a byte of it, so the miscount is
unreachable rather than argued away.

**A set beside a `[container]` is not that shape and is allowed.** The
set is cut over `carried_files`, which with a container is the
outermost VOLUMES - an archive's output, incompressible by the act of
having compressed it - so the payload never reaches par2gen however
compressible it is. That is what lets the two compose, and
`nc-r2c-store-over-a-compressed-inner-level` is the row that needs them
to.

`content` is also refused beside `same_as` (a dedupe copy's bytes are
another file's by definition and it draws none) and beside `zero_head`
(the head is applied last and would overwrite exactly the leading bytes
the shape exists to put there). And like `zero_head` it is stamped over
the drawn bytes IN PLACE, so adding it to a profile moves no later
file's bytes, no opaque name and no message-id.

**`[source] zero_head` fills a file's leading bytes with zeros.** It is
the padded-VOB and disk-image shape, and the only way a profile can put
two members in one post that share a first 16 KiB - which collides the
`(length, md5-16k)` key the live matcher pairs a wire file to a
descriptor on. A head has to clear 16,384 to collide that key at all.

It is not `periodic = true` returning by another name, and the schema
holds the line rather than trusting the author: every block past the
head is still unique stream noise, and a head at or past the set's own
`block_bytes` is refused, because that is the one length at which two
headed members would hand the creator an identical all-zero block. So a
profile with a recovery set has to state `block_bytes` before it may
state a head - which is what makes the refusal checkable from the file
rather than dependent on a block size the creator derives.

Which volume F3 flips a byte in, and which byte, come from the seed.
A profile cannot name a volume - how many there are is the WRITER's
decision, and a row that hard-coded "volume 2" would break the day the
framing moved by a byte - and the flip is bounded to the first bytes
past the archive signature so it stays a HEADER fault rather than
drifting into a file's data and becoming a payload fault under this
name.
