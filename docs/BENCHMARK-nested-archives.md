# Nested archives: which downloaders deliver the file, and what it costs

Seven downloaders over ten archive shapes. Each is graded on whether the file arrives
byte-correct with nobody touching it, and measured for the time, disk and processor it
takes to get there, including any manual work left behind.

Measured 27 August 2026 on an M3 Ultra desktop running macOS, against a local article
server. Every figure is the median of three independent passes.

## These are capability tests, not speed tests

> Each test asks whether a downloader can turn a post into the finished file on its own.
> The payloads are small and are served from memory over a local connection, with no
> provider and no network in the path, so **nothing here is limited by download speed**
> and the absolute times are far shorter than the same shapes would take in the real
> world.
>
> What carries across, and what does not: **whether a shape needs manual work at all is
> a property of the shape and the downloader**, not of file size or line speed, so those
> results transfer directly. Disk and processor figures scale with payload size, and the
> ratios between downloaders should hold. Elapsed time transfers least: against a real
> provider the download would dominate, so treat the seconds below as a comparison
> between downloaders doing identical work, never as a prediction of how long a real job
> takes.

## What each result means

| Result | Meaning |
|---|---|
| **No help needed** | Every file named in the post arrived under the downloader's output directory with a matching SHA-256, with nothing done by hand. |
| **Manual passes** | The downloader stopped early and left archives behind. The file was then produced by running the standard tools by hand, and the count is how many rounds of repair-and-extract that took. |
| **Never delivered** | The file could not be produced, even after the manual passes. Times and costs for these are the point at which the attempt was abandoned, not the cost of doing the work. |

Grading reads the bytes on disk, never a downloader's own report of success. A file
counts as delivered if its exact content appears anywhere in the output, so a downloader
that renames what it extracts is not penalised for it.

## The ten tests

### Test 1. Single layer

`Store RAR volumes + PAR2 -> file`

One store-mode RAR set with a posted PAR2 recovery set. No nesting.

**Why it matters.** The plain shape. A baseline every downloader is expected to finish.

*Field shape.* Routinely posted.

### Test 2. Archive in archive

`Store RAR + PAR2 -> store RAR -> file`

A store RAR wrapped inside another store RAR.

**Why it matters.** Wrapping hides the real filename until the outer layer is opened, so the post gives away less about what it contains.

*Obfuscation.* Wrapping of this kind is used to keep a post from revealing what it holds.

### Test 3. Compressed inner

`Store RAR + PAR2 -> compressed RAR -> file`

The same wrapper, but the inner archive is compressed rather than stored.

**Why it matters.** The inner layer has to be decompressed, not merely unwrapped.

*Obfuscation.* Wrapping of this kind is used to keep a post from revealing what it holds.

### Test 4. Mixed format

`Store RAR + PAR2 -> 7z (LZMA2) -> file`

A 7z archive inside a RAR set.

**Why it matters.** The format changes between layers, so one chain needs both engines.

*Structural.* Built to isolate one capability. Not claimed to be a common posting shape.

### Test 5. Damaged inner archive

`Healthy RAR + PAR2 -> damaged RAR + its own PAR2 -> file`

The posted set is intact. The archive inside it is corrupt, and its own PAR2 recovery set is packed alongside it.

**Why it matters.** A bad source or a partial re-post. The repair is needed on content that only exists once the outer archive has been opened.

*Field shape.* Routinely posted.

### Test 6. Five layers

`Store RAR + PAR2 -> store RAR x4 -> file`

A five-level ladder with a separate file at every level.

**Why it matters.** Deep wrapping, with content at each level, so reaching only the deepest file is not enough.

*Obfuscation.* Wrapping of this kind is used to keep a post from revealing what it holds.

### Test 7. Three formats

`Store RAR + PAR2 -> 7z -> store RAR -> file`

Three layers alternating between formats.

**Why it matters.** Format switching part-way down a chain.

*Structural.* Built to isolate one capability. Not claimed to be a common posting shape.

### Test 8. Damage at every level

`Damaged at all three layers, each with its own recovery data`

Every layer is corrupt. The outer has PAR2, the middle has its own PAR2 packed alongside, the innermost carries a RAR recovery record.

**Why it matters.** The full recovery chain. Each repair has to succeed before the next layer can be opened at all, and the three layers need three different tools.

*Structural.* Built to isolate one capability. Not claimed to be a common posting shape.

### Test 9. Recovery data only

`PAR2 at 100% only; the archive volumes are never delivered`

All four archive volumes are listed in the post and none arrives. Only a complete PAR2 set does.

**Why it matters.** A post whose articles are gone but whose recovery data survives. The archives have to be rebuilt from parity alone.

*Field shape.* Routinely posted.

### Test 10. Password chain

`Three encrypted layers, each password carried by the layer above`

Three password-protected layers. The first password is posted beside the volumes; each layer then contains the next one's password.

**Why it matters.** A password chain that has to be walked, one layer at a time. No downloader is given a password.

*Synthetic.* Constructed for this test. Our own sampling of current obfuscated posts found no password carried with the post, so this placement is not typical of the field.

Payloads are random data generated and archived locally, so the corpus contains no
third-party material and can be rebuilt from its generator.

## Did the downloader deliver the file

*Fewer manual passes is better.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | **No help needed** | **No help needed** | **No help needed** | **No help needed** | **No help needed** | **No help needed** | **No help needed** |
| Test 2 | 1 manual pass | 1 manual pass | **No help needed** | **No help needed** | **No help needed** | Never delivered | Never delivered |
| Test 3 | 1 manual pass | 1 manual pass | **No help needed** | **No help needed** | **No help needed** | Never delivered | Never delivered |
| Test 4 | 1 manual pass | 1 manual pass | **No help needed** | **No help needed** | **No help needed** | Never delivered | Never delivered |
| Test 5 | 1 manual pass | 1 manual pass | 1 manual pass | **No help needed** | 1 manual pass | Never delivered | Never delivered |
| Test 6 | 4 manual passes | 4 manual passes | 2 manual passes | **No help needed** | **No help needed** | Never delivered | Never delivered |
| Test 7 | 2 manual passes | 2 manual passes | **No help needed** | **No help needed** | **No help needed** | Never delivered | Never delivered |
| Test 8 | 3 manual passes | 3 manual passes | 3 manual passes | **No help needed** | Never delivered | Never delivered | Never delivered |
| Test 9 | **No help needed** | **No help needed** | Never delivered | **No help needed** | **No help needed** | Never delivered | **No help needed** |
| Test 10 | 3 manual passes | 3 manual passes | Never delivered | **No help needed** | Never delivered | 3 manual passes | 3 manual passes |

| Downloader | Delivered with no help | Needed manual passes | Never delivered |
|---|---:|---:|---:|
| NZBGet 26.3 | 2 | 8 | 0 |
| NZBGet 27.0-testing | 2 | 8 | 0 |
| SABnzbd 5.1.2 | 5 | 3 | 2 |
| nzbfast 1.2.4 | 10 | 0 | 0 |
| rustnzb 1.4.5 | 7 | 1 | 2 |
| Weaver 0.7.8 | 1 | 1 | 8 |
| Weaver 0.8.3 | 2 | 1 | 7 |

*More in the first column is better; more in the last is worse.*

## Time, split into downloader and manual work

*Lower is better, seconds. The first figure is the downloader's own run; the second,
where present, is the manual repair and extraction needed afterwards.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 4.2 | 4.2 | 4.1 | 0.7 | 4.1 | 2.1 | 2.1 |
| Test 2 | 4.2 + 0.3 | 4.2 + 0.3 | 6.1 | 0.7 | 4.1 | gave up at 6.1 | gave up at 2.1 |
| Test 3 | 4.2 + 0.3 | 4.2 + 0.3 | 6.1 | 0.7 | 4.1 | gave up at 6.1 | gave up at 2.1 |
| Test 4 | 4.2 + 0.4 | 4.2 + 0.4 | 6.1 | 2.2 | 4.1 | gave up at 6.1 | gave up at 4.1 |
| Test 5 | 6.3 + 17.3 | 6.2 + 17.5 | 6.1 + 17.3 | 4.5 | 4.1 + 17.3 | gave up at 6.1 | gave up at 2.1 |
| Test 6 | 4.2 + 1.1 | 4.2 + 1.1 | 2.0 + 0.3 | 0.6 | 2.1 | gave up at 6.2 | gave up at 2.1 |
| Test 7 | 4.2 + 0.4 | 4.2 + 0.4 | 4.1 | 1.0 | 2.1 | gave up at 6.2 | gave up at 2.1 |
| Test 8 | 6.2 + 12.2 | 6.2 + 12.3 | 2.1 + 12.3 | 2.2 | gave up at 2.1 | gave up at 99.1 | gave up at 240 |
| Test 9 | 6.2 | 6.2 | gave up at 2.1 | 2.9 | 47.5 | gave up at 2.1 | 4.1 |
| Test 10 | 2.2 + 4.6 | 2.2 + 4.6 | gave up at 301 | 0.6 | gave up at 2.1 | 609 + 4.6 | 38.6 + 4.6 |

## Total time to a usable file

*Lower is better, seconds.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 4.2 | 4.2 | 4.1 | 0.7 | 4.1 | 2.1 | 2.1 |
| Test 2 | 4.5 | 4.5 | 6.1 | 0.7 | 4.1 | not delivered | not delivered |
| Test 3 | 4.5 | 4.5 | 6.1 | 0.7 | 4.1 | not delivered | not delivered |
| Test 4 | 4.6 | 4.6 | 6.1 | 2.2 | 4.1 | not delivered | not delivered |
| Test 5 | 23.5 | 23.8 | 23.4 | 4.5 | 21.4 | not delivered | not delivered |
| Test 6 | 5.3 | 5.3 | 2.4 | 0.6 | 2.1 | not delivered | not delivered |
| Test 7 | 4.6 | 4.6 | 4.1 | 1.0 | 2.1 | not delivered | not delivered |
| Test 8 | 18.4 | 18.5 | 14.3 | 2.2 | not delivered | not delivered | not delivered |
| Test 9 | 6.2 | 6.2 | not delivered | 2.9 | 47.5 | not delivered | 4.1 |
| Test 10 | 6.8 | 6.8 | not delivered | 0.7 | not delivered | 614 | 43.3 |

## Total data written to disk

*Lower is better, GB. Physical bytes written by the downloader and by any manual passes
together, including intermediate files that were written and later removed.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 3.00 | 2.99 | 3.52 | 1.50 | 3.11 | 3.01 | 3.01 |
| Test 2 | 4.42 | 4.37 | 4.97 | 1.50 | 4.63 | 4.50 &dagger; | 4.50 &dagger; |
| Test 3 | 4.39 | 4.39 | 4.94 | 1.50 | 4.54 | 4.50 &dagger; | 4.50 &dagger; |
| Test 4 | 4.43 | 4.36 | 4.96 | 1.50 | 4.56 | 4.50 &dagger; | 4.50 &dagger; |
| Test 5 | 6.20 | 6.21 | 8.19 | 4.65 | 7.89 | 4.81 &dagger; | 4.81 &dagger; |
| Test 6 | 5.10 | 5.38 | 3.72 | 0.52 | 1.99 | 1.53 &dagger; | 1.53 &dagger; |
| Test 7 | 2.27 | 2.30 | 1.96 | 0.51 | 1.03 | 1.50 &dagger; | 1.50 &dagger; |
| Test 8 | 3.96 | 3.92 | 4.33 | 2.00 | 0.50 &dagger; | 1.73 &dagger; | 11.10 &dagger; |
| Test 9 | 1.06 | 1.05 | 0.02 &dagger; | 0.77 | 0.85 | 0.38 &dagger; | 1.13 |
| Test 10 | 2.42 | 2.37 | 3.85 &dagger; | 1.16 | 0.41 &dagger; | 2.40 | 2.37 |

&dagger; the file was never produced, so this is what the attempt cost before it was abandoned.

## Peak free space needed

*Lower is better, GB. The largest the working set ever became at one moment.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 3.02 | 3.02 | 3.01 | 1.50 | 3.20 | 3.00 | 3.00 |
| Test 2 | 3.01 | 3.01 | 3.01 | 1.50 | 4.73 | 4.50 &dagger; | 4.50 &dagger; |
| Test 3 | 3.01 | 3.01 | 3.00 | 1.50 | 4.65 | 4.50 &dagger; | 4.50 &dagger; |
| Test 4 | 3.01 | 3.01 | 3.00 | 1.50 | 4.73 | 3.00 &dagger; | 3.00 &dagger; |
| Test 5 | 4.66 | 4.66 | 4.66 | 3.10 | 5.04 | 3.30 &dagger; | 3.30 &dagger; |
| Test 6 | 2.56 | 2.56 | 1.52 | 0.51 | 2.98 | 1.52 &dagger; | 1.02 &dagger; |
| Test 7 | 1.50 | 1.50 | 1.00 | 0.50 | 1.97 | 1.00 &dagger; | 1.00 &dagger; |
| Test 8 | 2.09 | 2.09 | 2.09 | 1.28 | 0.87 &dagger; | 0.98 &dagger; | 3.36 &dagger; |
| Test 9 | 1.12 | 1.05 | 0.03 &dagger; | 0.75 | 1.10 | 0.38 &dagger; | 1.09 |
| Test 10 | 1.51 | 1.51 | 1.14 &dagger; | 1.10 | 0.41 &dagger; | 1.51 | 1.51 |

## Peak memory

*Lower is better, GB.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 0.14 | 0.14 | 1.65 | 0.08 | 0.05 | 0.48 | 0.49 |
| Test 2 | 0.14 | 0.13 | 1.64 | 0.08 | 0.05 | 0.48 &dagger; | 0.47 &dagger; |
| Test 3 | 0.14 | 0.14 | 1.63 | 0.07 | 0.05 | 0.49 &dagger; | 0.48 &dagger; |
| Test 4 | 0.14 | 0.13 | 1.72 | 4.32 | 0.12 | 0.49 &dagger; | 0.49 &dagger; |
| Test 5 | 0.15 | 0.16 | 1.67 | 0.32 | 0.06 | 0.51 &dagger; | 0.48 &dagger; |
| Test 6 | 0.13 | 0.14 | 1.04 | 0.09 | 0.05 | 0.33 &dagger; | 0.29 &dagger; |
| Test 7 | 0.14 | 0.13 | 1.10 | 1.25 | 0.05 | 0.30 &dagger; | 0.28 &dagger; |
| Test 8 | 0.14 | 0.16 | 0.99 | 0.30 | 0.04 &dagger; | 0.48 &dagger; | 0.46 &dagger; |
| Test 9 | 0.60 | 0.61 | 0.16 &dagger; | 1.29 | 1.28 | 0.36 &dagger; | 0.43 |
| Test 10 | 0.12 | 0.12 | 0.68 &dagger; | 0.16 | 0.04 &dagger; | 0.24 | 0.26 |

## Total processor time

*Lower is better, seconds. Processor seconds used by the downloader and by any manual
passes together, independent of how many cores the machine has.*

| Test | NZBGet 26.3 | NZBGet 27.0-testing | SABnzbd 5.1.2 | nzbfast 1.2.4 | rustnzb 1.4.5 | Weaver 0.7.8 | Weaver 0.8.3 |
|---|---|---|---|---|---|---|---|
| Test 1 | 3.0 | 3.0 | 3.4 | 1.2 | 14.1 | 2.0 | 1.6 |
| Test 2 | 4.2 | 4.1 | 3.9 | 1.4 | 13.9 | 2.8 &dagger; | 2.1 &dagger; |
| Test 3 | 4.1 | 4.0 | 3.9 | 1.4 | 14.0 | 2.8 &dagger; | 2.1 &dagger; |
| Test 4 | 4.3 | 4.3 | 4.2 | 2.7 | 14.0 | 3.8 &dagger; | 3.2 &dagger; |
| Test 5 | 24.9 | 25.2 | 25.7 | 6.3 | 36.2 | 3.0 &dagger; | 2.3 &dagger; |
| Test 6 | 2.8 | 2.9 | 2.7 | 0.7 | 4.8 | 1.1 &dagger; | 0.9 &dagger; |
| Test 7 | 2.0 | 1.8 | 2.0 | 1.0 | 4.6 | 1.4 &dagger; | 1.3 &dagger; |
| Test 8 | 17.6 | 17.7 | 18.8 | 6.5 | 4.2 &dagger; | 281 &dagger; | 247 &dagger; |
| Test 9 | 30.2 | 30.2 | 1.3 &dagger; | 41.2 | 890 | 1.6 &dagger; | 8.5 |
| Test 10 | 8.9 | 8.8 | 21.3 &dagger; | 0.8 | 3.1 &dagger; | 822 | 135 |

&dagger; the file was never produced. These are the cost of abandoning the job, not of
completing it, and are not comparable with the rest of the column.

## The same work, side by side

Downloaders complete different subsets of these tests, so a total across all ten is not
a like-for-like comparison. The table below covers **Tests 1 to 7**, the largest set of tests that
every downloader in it delivered.

| Downloader | Time to a usable file (s) | Data written (GB) |
|---|---:|---:|
| NZBGet 26.3 | 51.2 | 29.83 |
| NZBGet 27.0-testing | 51.5 | 29.99 |
| SABnzbd 5.1.2 | 52.3 | 32.27 |
| nzbfast 1.2.4 | 10.3 | 11.68 |
| rustnzb 1.4.5 | 41.8 | 27.75 |

*Lower is better in both columns.* Not shown, because they could not deliver enough of
that set to compare: Weaver 0.7.8 delivered 1; Weaver 0.8.3 delivered 1, of these 7.
A downloader that finishes little accumulates little time and little disk, so including
it here would give it the best-looking numbers on the table.

## Method

- **No provider is involved.** Every article is served from memory over a local connection, so results do not depend on a Usenet account, a provider's retention or a network path.
- **Each downloader is configured to its documented best**, not to its shipped defaults where those are slower.
- **No downloader is given a password.** On Test 10 the first password is posted beside the archive volumes, so the chain is available to anything that looks for it.
- **The manual passes use standard tools only** and do only what a person could: repair with PAR2, apply a RAR recovery record, extract, and read a password from a file that was posted in the clear. They never re-download and never use knowledge of the expected result to decide what to do.
- **The manual passes run for every downloader**, including those that finished on their own, where they find nothing to do. Post-processing only the ones that struggled would not be a comparison.
- **Every figure is the median of three independent passes.** Timing on this machine varies by around a quarter between repeats of the same work, so a single reading is not a measurement.
- **Every downloader ran as native code**, confirmed by sampling each running process throughout. None ran under emulation.

## Versions

nzbfast 1.2.4, NZBGet 26.3 and 27.0-testing-20260827, SABnzbd 5.1.2, rustnzb 1.4.5,
Weaver 0.7.8 and 0.8.3. rustnzb 1.4.5 and Weaver 0.8.3 are built from source because
their projects publish no macOS binary for those versions; every other one is the
published build.
