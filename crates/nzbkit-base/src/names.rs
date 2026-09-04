//! File-naming rules for posted release files: the shared stem a whole
//! set reduces to, the volume sort order, and the "this container IS the
//! deliverable" extension guard. Pure functions over names - no extractor
//! state - moved out of `extract/mod.rs` bodily so that file stays inside
//! its size-gate baseline (TODO 106 pattern; re-exported from `mod.rs`,
//! so every `nzbkit::extract::release_stem` caller is unchanged).

/// Strip release-file suffixes down to the shared stem:
/// `x.part01.rar`/`x.r00`/`x.vol000+01.par2`/`x.par2`/`x.rar` → `x`,
/// and split-container volumes `x.7z.001`/`x.zip.001` → `x.7z`/`x.zip`
/// (the container extension stays: it is the shared base every part
/// and its par2 sidecar reduce to, mirroring `sevenz_part_name`).
///
/// The split rule exists because without it a 100-part obfuscated 7z
/// set indexes as 100 half-GB "releases" - found live 2 Aug 2026 via
/// the Supergirl acceptance case (122 rows, 67 GB) - which hides the
/// set's true size from everything that reasons about it.
pub fn release_stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut end = lower.len();
    let cut = |s: &str, end: usize, f: &dyn Fn(&str) -> Option<usize>| -> usize {
        f(&s[..end]).unwrap_or(end)
    };
    end = cut(&lower, end, &|s| s.strip_suffix(".par2").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        // par2cmdline "vol01+02", range-style "vol001-003", or the
        // bare-ordinal "vol-01". One rule, shared with the deferral
        // classifier in nzb::kind() - this cut and that classifier
        // drifted apart once (both missing `.vol-NN`), which left the
        // ordinal on the stem and shattered the release in the index.
        crate::nzb::par2_vol_suffix(s)
    });
    end = cut(&lower, end, &|s| {
        // Split-container volume: 3-4 digit tail (7-Zip names volumes
        // `%s.%03d`, four digits past 999 - same bounds as
        // `sevenz_part_name`) directly after a container extension.
        // One and two digits stay: `Track.01` is somebody's music.
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let head = &s[..p];
        (head.ends_with(".7z") || head.ends_with(".zip")).then_some(p)
    });
    end = cut(&lower, end, &|s| s.strip_suffix(".rar").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let p = s.rfind(".part")?;
        let tail = &s[p + 5..];
        (!tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())).then_some(p)
    });
    end = cut(&lower, end, &|s| {
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        // Old-style continuations roll past .r99 into .s00 … .z99 (and
        // vol_sort_key already orders that whole range) - accepting only
        // r/s here left .t00+ volumes with their extension in the stem,
        // splitting 200+ volume sets across "releases" and starving the
        // repair path's stem filter of everything past .s99.
        if !(tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && tail[1..].bytes().all(|c| c.is_ascii_digit()))
        {
            return None;
        }
        // `x264` and `x265` fit that grammar exactly, so a codec sitting
        // behind a resolution or a source is refused here - see
        // `release::codec_behind_quality`, which owns the rule and the
        // measurement, and which is deliberately a CONJUNCTION: the
        // r-z range above must not be narrowed and neither test alone
        // is safe.
        let head = &s[..p];
        let head_last = head.rsplit('.').next().unwrap_or(head);
        (!crate::release::codec_behind_quality(head_last, tail)).then_some(p)
    });
    name[..end].to_string()
}

/// Extensions whose bytes ARE a RAR or 7z container but whose file is
/// the deliverable: `.cbr` is a comic wearing a RAR wrapper, `.cb7` its
/// 7-Zip twin. Unpacking one is data loss, not extraction - the user
/// asked for the comic, not a folder of loose pages (GitHub issue #40).
/// The zip family's counterpart list (`.cbz`, `.epub`, office files)
/// lives in `zip::FINAL_FILE_EXTS`; the same standing rule applies here:
/// the guard keys on the NAMED extension only, so an obfuscated post
/// (hash names, no meaningful extension) still earns the magic sniff.
const FINAL_FILE_EXTS: &[&str] = &["cbr", "cb7"];

/// A RAR/7z-container file whose extension marks it as the payload
/// itself. Never unpack one - and never let a sweep count it as a spent
/// volume or nested layer.
pub fn is_final_file(path: &std::path::Path) -> bool {
    path.file_name()
        .is_some_and(|n| is_final_name(&n.to_string_lossy()))
}

/// [`is_final_file`] over a bare file name (any case).
///
/// Reads the extension through [`crate::disk::trimmed_extension`], not
/// `Path::extension()`: a trailing dot or space - the exact tail Windows
/// folds away - defeats `Path::extension()` and answered `false` on
/// `comic.cbr.` and `comic.cbr `, earning the comic the RAR chase (T6).
pub fn is_final_name(name: &str) -> bool {
    crate::disk::trimmed_extension(name)
        .is_some_and(|e| FINAL_FILE_EXTS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Extensions that positively identify FINISHED PAYLOAD CONTENT - the
/// file a user asked for, not packaging around one. Video, audio, disc
/// images, subtitles, stills and the small release sidecars.
///
/// DELIBERATELY NOT [`FINAL_FILE_EXTS`], which is a different statement:
/// that list is containers whose bytes really ARE a RAR or 7z and whose
/// FILE is nonetheless the deliverable (`.cbr` is a comic in a RAR
/// wrapper). These are names that say the file is not an archive at all.
/// Folding the two together would make `is_final_name` - which several
/// callers read as "unpacking this destroys it" - mean something looser
/// than it does.
///
/// It is a DENY list and not an allow list, and that was measured rather
/// than chosen. The eligible population is open-ended and POSTER-defined:
/// this product's own model of an obfuscated post is `bbbb1234.bin`, and
/// nine tests in this crate feed hash names carrying `.bin` (see
/// `obfuscated_names_group_by_inner_file`, `nested_split_chain`,
/// `the_materialized_hook_names_the_renamed_volume`). An allow list of
/// "RAR-shaped or extensionless" was built first and broke every one of
/// them - which is the worst regression this product has, because the
/// obfuscated set is the one the whole one-pass path exists for. The
/// population to PROTECT, by contrast, is small and nameable, and every
/// name missing from it costs a missed protection rather than a broken
/// download.
///
/// A SECOND video-extension list exists one crate over - `smart::VIDEO_EXTS`,
/// which feeds the naming, keep-media and sample sweeps - and the two
/// CANNOT be shared (nzbkit does not depend on nzbfast) and must not be
/// silently unified if that ever changes: this list answers "may the
/// bytes overrule the name", that one answers "is this file the
/// feature", and they are free to disagree. `smart::videoext` reached
/// the same principle independently on the same day ("a NAMED extension
/// is authoritative and is never second-guessed"), which is the
/// corroboration, not a reason to merge them.
const PAYLOAD_CONTENT_EXTS: &[&str] = &[
    // Video, including the disc images `largest_video` treats as the
    // feature in their own right.
    "mkv", "mk3d", "mp4", "m4v", "avi", "mov", "wmv", "mpg", "mpeg", "m2ts", "mts", "ts", "vob",
    "webm", "ogm", "divx", "flv", "rmvb", "iso", "img", //
    // Audio.
    "mp3", "flac", "m4a", "mka", "aac", "ac3", "dts", "wav", "ogg", "opus", "wma", //
    // Subtitles, stills and the small sidecars a release posts beside
    // its volumes - none of which is ever a RAR volume.
    "srt", "sub", "idx", "ass", "ssa", "nfo", "sfv", "txt", "jpg", "jpeg", "png", "gif", "pdf",
];

/// Does this name positively identify the file as finished payload?
fn payload_content_name(lower: &str) -> bool {
    std::path::Path::new(lower)
        .extension()
        .is_some_and(|e| PAYLOAD_CONTENT_EXTS.contains(&&*e.to_string_lossy()))
}

/// May the offset-0 sniff read this POSTED name's bytes as a RAR or 7z
/// container (subject to the magic check the caller performs)?
///
/// THE NAME WINS WHENEVER THE NAME IDENTIFIES THE CONTENT, and the reason
/// is that the two mistakes are not the same size. Decline a RAR that was
/// posted as `Movie.mkv` and the file materializes whole: every byte
/// arrived and the user has the file they asked for, under the name it
/// was posted under. Believe the
/// MAGIC on a real movie whose first bytes happen to read `Rar!` -
/// crafted, or a container genuinely embedded in a disc dump - and the
/// movie is GONE, replaced by whatever the archive claimed, with the job
/// reporting Completed. Declining can only ever cost speed; believing can
/// cost the file. That asymmetry is the whole rule.
///
/// Measured on origin/main 30 Aug 2026 (matrix row M4-90). A real RAR
/// volume at byte 0 was unpacked and the named file vanished from the
/// tree under EVERY name tried - `Movie.mkv`, `Movie.mp4`, `disc.iso`,
/// `Subs.srt` - and a real 7z did the same. So this is not a new policy:
/// it is the rule `zip::chase_eligible_name` and `tar::chase_eligible_name`
/// have carried for as long as they have existed ("a NAMED file that is
/// not a tar is never magic-sniffed"), applied to the two arms that never
/// got one. Both of those declined `Movie.mkv` on the same bytes in the
/// same run, which is what a working name gate looks like.
///
/// ONE function for both formats, deliberately. Two predicates is how a
/// sniffer ends up believing the UNION of two individually-correct rules,
/// and this file has already watched `release_stem` and `nzb::kind()`
/// drift apart once.
///
/// An obfuscated post keeps the sniff (matrix row M4-75): a hash name is
/// the ABSENCE of evidence, not weaker evidence, so the content magic is
/// the strongest thing available and under the family rule it may
/// finalize. That half is a PASS pin and it is the control arm - anybody
/// who answers a future polyglot report by widening this list onto `.bin`
/// or onto extensionless names takes every obfuscated set in production
/// with it.
///
/// THE STATED COST, and it GREW on 31 Aug 2026 when the disk half below
/// closed. Until then an obfuscator dressing its volumes as `.mkv` only
/// lost the one-pass path: the post-pass gated RAR and 7z on
/// [`is_final_name`] alone, so it unpacked the materialized file anyway.
/// Now nothing unpacks it, and the cost is the whole extraction - the
/// user gets a file named `Movie.mkv` whose bytes are a RAR, which they
/// can open by hand. That is deliberate and it is the SAME trade one
/// notch further along: a wrongly-declined file is whole and openable, a
/// wrongly-unpacked one is gone. No such shape is in this repo's corpus,
/// and the obfuscated set that IS - `bbbb1234.bin` - is untouched,
/// because a hash name is eligible under both halves.
///
/// THE DISK HALF IS CLOSED, 31 Aug 2026, and until then this gate was
/// not end-to-end protection. `unpack::is_extractable_archive` asks the
/// same question of a file that has already landed on disk and gated RAR
/// and 7z on `is_final_file` alone - exactly the hole closed here - while
/// deferring to `zip::is_container` and `is_tar_container` for their own
/// name rules, the same four-way asymmetry one layer down. Measured on
/// that function directly, twice, 30 and 31 Aug: `Movie.mkv`, `disc.iso`
/// and `Subs.srt` carrying RAR5 magic all answered `extractable = true`
/// and only `.cbr` did not. So a named polyglot declined HERE
/// materialized whole and was then picked up as an entry archive,
/// unpacked, and swept, and the JOB-level outcome for matrix row M4-90
/// did not change at all.
///
/// It was not one call, which is why it was a row of its own. EIGHT disk
/// sites spelled `!is_final_file(p) && magic(p)` - the entry-archive
/// list, `collect_obfuscated_rar_volumes` (whose caller DELETES what it
/// spends), `collect_sevenz_archives`, the `pre_obfuscated` census, the
/// nested-layer census, `nested_inner_kind`, the split-join base gate and
/// the join sweep's keep-guard - and one more had to move with them: the
/// stray-archive door, which reports `no extractor claimed it` as a
/// FAILED job, and which would otherwise have turned every declined
/// polyglot into a failure. All nine now call [`archive_sniff_eligible`].
/// `zip::is_container` and `is_tar_container` needed nothing: both were
/// already right, which is what made the asymmetry visible.
///
/// Self-extractors are NOT judged here. `sfx_archive_behind_stub` asks
/// its own name question (`is_sfx_name`: `.exe`/`.bin`/`.sfx`) about a
/// signature at a NON-ZERO offset, and the caller keeps that arm ahead of
/// this one - two different questions, two gates, neither standing in for
/// the other. That is also why `.bin` is absent from the list above and
/// must stay absent: it is this product's commonest obfuscated-volume
/// extension, so denying it to close matrix row M4-101 would break the
/// obfuscated path outright. M4-101 needs an answer that is not a name.
/// Callers keep their own `payload_name` ([`is_final_name`]) test beside
/// this one and that redundancy is deliberate: `payload_name` is threaded
/// through several arms from one read and answers a DIFFERENT question
/// (is this container the deliverable), so neither is dead code for the
/// other.
pub fn archive_sniff_eligible_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !is_final_name(&lower) && !payload_content_name(&lower)
}

/// [`archive_sniff_eligible_name`] over a path, for the DISK half of the
/// rule - the same relation [`is_final_file`] has to [`is_final_name`].
///
/// It exists so the post-pass's eight sites read the same name as the
/// stream's, rather than each spelling `!is_final_file(p) && magic(p)`
/// again. That spelling IS the defect this closes: eight independent
/// writings of one question is how four of them ended up answering it
/// differently, which is the same argument `archive_sniff_eligible_name`
/// makes above for being ONE function across RAR and 7z.
///
/// A path with no file name answers false: there are no bytes to sniff.
pub fn archive_sniff_eligible(path: &std::path::Path) -> bool {
    path.file_name()
        .is_some_and(|n| archive_sniff_eligible_name(&n.to_string_lossy()))
}

/// Natural volume order key: `.rar` < `.r00` < `.r01`; `.part1` < `.part2`.
pub fn vol_sort_key(name: &str) -> (u64, String) {
    let lower = name.to_ascii_lowercase();
    if let Some(p) = lower.rfind(".part") {
        let tail = &lower[p + 5..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            return (n, lower.clone());
        }
    }
    if lower.ends_with(".rar") {
        return (0, lower.clone());
    }
    if let Some(p) = lower.rfind('.') {
        let tail = &lower[p + 1..];
        // Old-style continuations roll the letter past .r99: .s00 = 101,
        // .t00 = 201… (each letter is another 10^digits volumes). Keying
        // only 'r' broke base-resolution at the r→s boundary on 100+
        // volume sets.
        if tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && let Ok(n) = tail[1..].parse::<u64>()
        {
            let span = 10u64.pow((tail.len() - 1) as u32);
            return (
                (tail.as_bytes()[0] - b'r') as u64 * span + n + 1,
                lower.clone(),
            );
        }
        // WinRAR numeric volume naming: .001, .002 …
        if tail.len() >= 2
            && tail.bytes().all(|c| c.is_ascii_digit())
            && let Ok(n) = tail.parse::<u64>()
        {
            return (n, lower.clone());
        }
    }
    (u64::MAX, lower)
}
