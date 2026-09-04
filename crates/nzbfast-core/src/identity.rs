//! What a finished download actually IS, when the name it was posted
//! under does not say.
//!
//! Four independent enrichers, each one operating only on facts already
//! in hand at the moment a job completes. None of them fetches an
//! article; none of them runs a background sweep; every one of them
//! degrades to silence offline.
//!
//! - **srrdb archive-CRC** (`crate::srrdb`): the RAR headers we already
//!   read state an inner file's CRC32, which is an exact key to a
//!   canonical scene name and an IMDb id.
//! - **PAR2 hash16k repost table** (`Index::par_hash_lookup`): the
//!   sidecar fingerprints the OUTER volumes, so it identifies a repost
//!   of something we named before even when the archive headers are
//!   encrypted. The one path here that survives `-hp`. It is also the
//!   only rung with MEMORY, so it is the only one whose mistakes
//!   outlive the job that made them - which is why what it stores
//!   beside a name is the EVIDENCE that proved it, why a later proof
//!   can correct a name a weak lane taught, and why a fingerprint two
//!   equally-evidenced jobs called different things is refused rather
//!   than answered (`par_hash_remember`, W7-01..03). hash16k is the
//!   identical-head twin family, so declining is not caution, it is
//!   the same rule the in-job tiers follow.
//! - **Matroska Title** (`nzbkit::mkv`): the muxer's own name for the
//!   file, which a reposter who scrambled the subject line usually
//!   never reached inside the container to clear.
//! - **xREL P2P** (`crate::xrel`): not a name at all - an IMDb id for
//!   the true-P2P groups whose releases the scene predbs never carry.
//!
//! The result is a SECOND opinion recorded beside the posted name, never
//! a replacement for it: `Job::name` is what the user and the *arrs
//! match on. Renaming reads the second opinion; the API reports both.
//!
//! The decision logic is pure and lives here; the fetching is in the two
//! client modules. That split is what lets the ladder be tested without
//! a network, and it is also what keeps the rate-limited calls
//! conditional - `xrel_query` decides whether a request is worth making
//! before one is made.

use nzbkit::release;

/// The one opt-in that lets a unit-test build reach a real service.
///
/// Set it to run the five `#[ignore]`d live provider rigs in
/// `wall/tests.rs`, whose whole point is to catch a provider that has
/// died SILENTLY (HTTP 200, empty body) - the failure no fixture can
/// see. Nothing else should ever set it, and nothing in CI does.
pub const TEST_CALLOUT_ALLOW: &str = "NZBFAST_TEST_ALLOW_CALLOUT";

/// May this process put an enrichment request on the wire at all?
///
/// The single source for CLAUDE.md invariant 5. `NZBFAST_NO_ENRICH` is
/// the test suite's "do not touch the real internet" switch, and every
/// metadata lane is enrichment by another name - without the guard,
/// every end-to-end daemon test whose fixture name carries a group tag
/// would put a live xREL search on the wire.
///
/// Checked at the network boundary inside each client rather than at
/// the call sites, so a new call site cannot forget it. The LOCAL rungs
/// (the repost table, the container Title) are unaffected and stay
/// testable end to end. The lane switches that used to spell the same
/// env read inline - the enrichment workers, the byte prober, pesto,
/// the scoreboard sampler, the predb seed importer and the confirm
/// ticker - all ask HERE now, so there is one rule and one copy of it,
/// and `NZBFAST_NO_ENRICH=0` no longer means "off" at four sites and
/// "on" at three.
///
/// **In a unit-test build the answer is NO by default, whatever the
/// environment says.** An env-var-only guard is a property of how the
/// RUNNER was invoked, not of the code: the same binary run without the
/// variable dials the open internet, and a test cannot hold an
/// invariant it does not state. Measured 1 Sep 2026 - `1dbcca3c2`
/// changed the confirm lane's pick order so `expected_next` runs first,
/// and THREE tests in the `--bin nzbfast` target began calling
/// api.tvmaze.com the moment the variable was absent (two of them
/// failing, one dialling out and passing anyway). `cfg!(test)` is a
/// property of the BUILD, so it holds either way; it is set only for
/// this crate's own unit-test build, so the integration suites - which
/// spawn the shipped binary as a subprocess and set the variable
/// themselves - and nzbfast-ffi, which compiles this module tree as a
/// dependency, are both untouched. Full record:
/// `research/RED-UNIT-ONE-PROCESS-1dbcca3c2-IS-ENRICH-DEPENDENT-2026-09-01.md`.
///
/// **`test-support` is the other half of that, and it is load-bearing
/// rather than belt.** `cfg!(test)` is a property of the build of ONE
/// CRATE, and since the crate-split step 2 cut this module is
/// `nzbfast-core` - which nzbfast's own unit tests compile as an
/// ordinary DEPENDENCY, with `cfg(test)` off. So the sentence above
/// stopped being true for the ~1,750 tests it was written for the
/// moment the cut landed, and four control arms in nzbfast went red
/// saying so (`tests_grabs::a_unit_test_may_not_reach_a_named_host_
/// outside_loopback` and the three lane tests beside it). nzbfast turns
/// `test-support` on through a DEV dependency, so it is set whenever a
/// test target of nzbfast is built and clear in the release build,
/// which is what makes it the right cross-crate spelling of the same
/// question. The stated cost is the other direction: a build that
/// resolves dev-dependencies AND ships its binary would have
/// enrichment permanently off - loud (no metadata at all), not silent,
/// and no release path does it (`packaging/build-bundles.sh` is plain
/// `cargo build --release -p nzbfast`).
pub fn may_call_out() -> bool {
    if cfg!(test) || cfg!(feature = "test-support") {
        return std::env::var_os(TEST_CALLOUT_ALLOW).is_some();
    }
    std::env::var_os("NZBFAST_NO_ENRICH").is_none()
}

/// The second opinion, when there is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// A canonical release name to prefer when renaming. Empty when no
    /// oracle offered one, or when the posted name was already good.
    pub name: String,
    /// IMDb id in `tt` form, empty when nothing knew one.
    pub imdb: String,
    /// Which oracle answered - see the module note on why the user gets
    /// told this rather than just the name.
    pub src: &'static str,
}

impl Identity {
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.imdb.is_empty()
    }
}

/// What srrdb knows about one archive CRC.
///
/// Declared HERE rather than in `srrdb`, which is what fills it in,
/// because [`Facts`] below carries one and srrdb asks
/// [`may_call_out`] before it fetches - so the type living beside the
/// fetcher made these two modules need each other. The crate-split prep
/// (research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md) put the plain data
/// under the fetcher, which is the direction that has no cycle in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrrHit {
    /// The canonical scene release name ("Dune.Part.Two.2024.1080p.WEB.h264-ETHEL").
    pub release: String,
    /// IMDb id in `tt` form, empty when they hold none for it.
    pub imdb: String,
}

/// Everything the naming decision reads. Assembled by the caller so the
/// decision itself touches no disk and no network.
#[derive(Debug, Default)]
pub struct Facts {
    /// The name the job was submitted under.
    pub posted: String,
    /// srrdb's answer for this set's inner-file CRC32.
    pub srr: Option<SrrHit>,
    /// `(name, title_key)` from the PAR2 repost table.
    pub remembered: Option<(String, String)>,
    /// Segment>Info>Title of the payload's main video, credit already
    /// stripped.
    pub mkv_title: Option<String>,
}

/// Pick the best name available, and say where it came from.
///
/// Ordered by how much the answer is worth trusting, not by how much it
/// costs:
///
/// 1. **srrdb**, always when it answered. A CRC32 hit is the same bytes,
///    and what it returns is the release's canonical spelling - which
///    beats the posted name even when the posted name is perfectly
///    readable, because that is what a media server matches on.
/// 2. **The repost table**, when the posted name says nothing. An exact
///    fingerprint match against a release WE named, so it is as certain
///    as srrdb about identity and less certain only about spelling.
/// 3. **The container's Title**, when the posted name says nothing and
///    the Title reads as a release name. The weakest of the three: it is
///    an unverified claim by whoever muxed the file.
///
/// 2 and 3 are gated on the posted name being obfuscated because that is
/// the only case where they can improve on it. A readable posted name is
/// the submitter's own words, and replacing those on a container's say-so
/// would break the one thing the user is sure of.
pub fn decide_name(f: &Facts) -> Option<(String, &'static str)> {
    let posted = f.posted.trim();
    let take = |cand: &str, src: &'static str| -> Option<(String, &'static str)> {
        let cand = cand.trim();
        // A path is not a release name from ANY source. Refused whole
        // rather than sanitised: mapping the separators leaves a name
        // like ".. etc Film" - not an escape, but a hidden dotfile made
        // out of a string that was never a name in the first place.
        if cand.contains('/') || cand.contains('\\') || cand.starts_with('.') {
            return None;
        }
        let cand = release::sanitize_name(cand);
        // Nothing to say if it agrees with the name we already have, and
        // nothing usable if sanitising emptied it.
        (!cand.is_empty() && !cand.eq_ignore_ascii_case(posted)).then_some((cand, src))
    };
    if let Some(hit) = &f.srr
        && let Some(got) = take(&hit.release, "srrdb")
    {
        return Some(got);
    }
    // The whole-stem verdict: `blob.7z` is not a name, and reading it
    // as one skipped the two recoveries below entirely (M7, 10 Aug).
    if release::stem_is_a_name(posted) {
        return None;
    }
    if let Some((name, _)) = &f.remembered
        && let Some(got) = take(name, "par-hash")
    {
        return Some(got);
    }
    let title = f.mkv_title.as_deref()?;
    // The one candidate nobody vouched for, so it has to pass the
    // release-name bar on its own before it may rename anything.
    release::looks_like_release_name(title)
        .then(|| take(title, "mkv-title"))
        .flatten()
}

/// The query to ask xREL, or `None` for "do not spend a request".
///
/// Three gates, all of them about not making a pointless call on a
/// service with a 2-per-5-seconds search budget:
///
/// - an id we already hold answers the question, so nothing to ask;
/// - a name with no group tag is not a release xREL indexes;
/// - a name that reads as obfuscated has nothing to search WITH.
///
/// The query is the title and year rather than the whole release name:
/// xREL's search is a text search over its own catalogue, and handing it
/// "…2160p.WEB.H265-POKE" narrows to the tokens rather than the film.
pub fn xrel_query(name: &str, known_imdb: &str) -> Option<String> {
    if !known_imdb.trim().is_empty() {
        return None;
    }
    let name = name.trim();
    if !release::stem_is_a_name(name) || release::group_of(name).is_none() {
        return None;
    }
    let p = release::parse_release(name);
    let title = p.title.trim();
    if title.is_empty() {
        return None;
    }
    Some(match p.year {
        Some(y) => format!("{title} {y}"),
        None => title.to_string(),
    })
}

/// What a finished download's PAR2 sidecar says about its identity:
/// the Recovery Set ID (the set's own strong identity - the §131
/// claims layer's `par2-set-id` proving key) and the member-file
/// fingerprints the repost table keys on.
#[cfg(feature = "indexer")]
pub struct ParSidecar {
    /// Lowercase hex of the 16-byte Recovery Set ID.
    pub set_id: String,
    /// `(hash16k hex, member name)` per outer volume.
    pub pairs: Vec<(String, String)>,
}

/// Read the PAR2 sidecars sitting beside a finished download.
///
/// Sidecars only, and only the top level: `.par2` files are what the
/// post shipped, and the recovery volumes repeat the same critical
/// packets, so the index alone answers. Called BEFORE the cleanup sweep,
/// which is what deletes them.
#[cfg(feature = "indexer")]
pub fn par_sidecar(dir: &std::path::Path) -> Option<ParSidecar> {
    // A main index is small (tens of KB); a `.vol000+50.par2` is not,
    // and reading a 700 MB recovery volume to learn what its first
    // packet already said would stall the tail. Skip the big ones and
    // read the rest smallest-first, under a budget on TOTAL bytes.
    const MAX_READ: u64 = 8 << 20;
    const MAX_TOTAL: u64 = 32 << 20;
    let rd = std::fs::read_dir(dir).ok()?;
    let mut cands: Vec<(u64, std::path::PathBuf)> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
                && p.is_file()
        })
        .filter_map(|p| Some((p.metadata().ok()?.len(), p)))
        .filter(|(len, _)| *len <= MAX_READ)
        .collect();
    cands.sort();
    // One directory can hold more than one SET: a release's own, plus a
    // sample's or a subtitle pack's. Taking the first that parses means
    // taking the SMALLEST file, which is as likely to be the ancillary
    // set as the release's - and its fingerprint would then be filed as
    // this download's identity.
    //
    // So census EVERY candidate the budget affords rather than a fixed
    // count of them. A subtitle pack's index and three of its own
    // volumes all sort ahead of the release's index on size, so a count
    // window discarded the one set this function exists to find. The
    // budget is on bytes, which is what reading and parsing actually
    // cost, and the sort is ascending, so what it drops is the largest
    // volumes - which repeat packets the index already stated.
    let mut sets: std::collections::HashMap<String, Vec<(String, String)>> = Default::default();
    let mut spent = 0u64;
    for (len, path) in &cands {
        if spent + len > MAX_TOTAL {
            break;
        }
        spent += len;
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(set) = nzbkit::par2::Par2Set::parse(&[&bytes]) else {
            continue;
        };
        let pairs = set.member_hash16k();
        if pairs.is_empty() {
            continue;
        }
        // The same set again (a main index and its own volumes): keep
        // whichever copy described the most members.
        let have = sets
            .entry(nzbkit::par2::hex16(&set.recovery_set_id))
            .or_default();
        if pairs.len() > have.len() {
            *have = pairs;
        }
    }
    // The set describing the release is the one covering the most
    // members; a tie between two DIFFERENT sets is genuinely ambiguous,
    // and a wrong identity is worse than none.
    //
    // Decided over the FINISHED census, not carried along it: a `tied`
    // flag raised mid-scan outlived the tie, because a later fuller copy
    // of one of the two sets improved that set's count without clearing
    // it. The function then declined with a unique winner in hand.
    let most = sets.values().map(Vec::len).max()?;
    let mut winners = sets.into_iter().filter(|(_, pairs)| pairs.len() == most);
    let (set_id, pairs) = winners.next()?;
    if winners.next().is_some() {
        return None;
    }
    Some(ParSidecar { set_id, pairs })
}

/// The Matroska Title of a finished download's main video, with the
/// repacker credit stripped. `None` when the file is not Matroska, or
/// it carries no Title.
///
/// Takes the VIDEO and not the directory, since the crate-split prep
/// (step 1 of research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md).
/// Resolving it here meant calling `smart::main_video`, which put this
/// module - the plan's lowest layer - on top of the unpack one for a
/// path its single caller already knows how to ask for. The caller
/// resolves the feature and hands it over; which file "the main video"
/// means is still `smart::main_video`'s answer and nobody else's.
pub fn container_title(video: &std::path::Path) -> Option<String> {
    if !matches!(
        video
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
            .as_str(),
        "mkv" | "webm"
    ) {
        return None;
    }
    nzbkit::mkv::probe(video)?.title
}

/// The PAR2 index fixture builder, in a module of its own because
/// `serve::naming::repost_tests` needs it and that file is in
/// `nzbfast` - a layer above this crate since the crate-split step 2
/// cut, so a `#[cfg(test)]` module cannot carry it any more.
///
/// A second packet writer in that file is how two fixture builders
/// start disagreeing about the format they both claim to emit, which
/// is why it is shared rather than copied. Everything else in
/// `identity`'s test module stays private to it.
#[cfg(any(test, feature = "test-support"))]
pub mod testkit {
    /// The same builder with each member's `md5_16k` fill byte chosen by
    /// the caller. Two sets that must share EXACTLY ONE fingerprint -
    /// the W7-14 shape, one collision and no disagreement - cannot be
    /// spelled by picking `set` values: the derived byte is
    /// `set ^ i ^ 0x80`, so any overlap between two runs of consecutive
    /// `i` comes in twos.
    #[cfg(feature = "indexer")]
    pub fn par2_index_hashed(set: u8, members: &[(&str, u8)], pad: usize) -> Vec<u8> {
        use md5::{Digest, Md5};
        let pkt = |ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
            let mut p = Vec::new();
            p.extend_from_slice(nzbkit::par2::MAGIC);
            p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
            p.extend_from_slice(&[0u8; 16]); // packet MD5, patched below
            p.extend_from_slice(&[set; 16]); // recovery set id
            p.extend_from_slice(ptype);
            p.extend_from_slice(body);
            let md5: [u8; 16] = Md5::digest(&p[32..]).into();
            p[16..32].copy_from_slice(&md5);
            p
        };
        let fid = |i: usize| -> [u8; 16] { [set.wrapping_add(i as u8).wrapping_add(1); 16] };
        let mut main = Vec::new();
        main.extend_from_slice(&4096u64.to_le_bytes());
        main.extend_from_slice(&(members.len() as u32).to_le_bytes());
        for i in 0..members.len() {
            main.extend_from_slice(&fid(i));
        }
        let mut out = pkt(b"PAR 2.0\0Main\0\0\0\0", &main);
        for (i, (name, h16k)) in members.iter().enumerate() {
            let mut d = Vec::new();
            d.extend_from_slice(&fid(i));
            d.extend_from_slice(&[set ^ (i as u8) ^ 0x40; 16]); // whole-file md5
            d.extend_from_slice(&[*h16k; 16]); // md5_16k
            d.extend_from_slice(&(64u64 << 10).to_le_bytes());
            d.extend_from_slice(name.as_bytes());
            while !d.len().is_multiple_of(4) {
                d.push(0);
            }
            out.extend(pkt(b"PAR 2.0\0FileDesc", &d));
        }
        out.extend(pkt(
            b"PAR 2.0\0Creator\0",
            &vec![b'x'; pad.next_multiple_of(4)],
        ));
        out
    }
}

/// Private throughout: the one item another crate needed is in
/// [`testkit`] above.
#[cfg(test)]
mod tests {
    #[cfg(feature = "indexer")]
    use super::testkit::par2_index_hashed;
    use super::*;

    fn srr(release: &str) -> Option<SrrHit> {
        Some(SrrHit {
            release: release.into(),
            imdb: "tt1".into(),
        })
    }

    const OBF: &str = "a4f9c2e1b7d0483951";
    const GOOD: &str = "Example.Movie.2019.1080p.BluRay.x264-GRP";
    const CANON: &str = "Example.Movie.2019.1080p.BluRay.x264-CANON";

    /// An exact CRC hit outranks everything, INCLUDING a readable posted
    /// name: it is the release's canonical spelling and that is what a
    /// media server matches on.
    #[test]
    fn an_exact_crc_hit_wins_even_over_a_readable_name() {
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(CANON),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), Some((CANON.to_string(), "srrdb")));
    }

    /// The weaker two only speak when the posted name says nothing. A
    /// readable name is the submitter's own words and a container's
    /// claim does not get to overrule them.
    #[test]
    fn the_weaker_oracles_stay_quiet_over_a_readable_name() {
        let f = Facts {
            posted: GOOD.into(),
            remembered: Some((CANON.into(), "m:x".into())),
            mkv_title: Some(CANON.into()),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
    }

    #[test]
    fn an_obfuscated_name_takes_the_repost_table_then_the_container() {
        let remembered = Facts {
            posted: OBF.into(),
            remembered: Some((GOOD.into(), "m:example movie:2019".into())),
            mkv_title: Some(CANON.into()),
            ..Default::default()
        };
        // The fingerprint is exact; the container's claim is not.
        assert_eq!(
            decide_name(&remembered),
            Some((GOOD.to_string(), "par-hash"))
        );

        let container = Facts {
            posted: OBF.into(),
            mkv_title: Some(GOOD.into()),
            ..Default::default()
        };
        assert_eq!(
            decide_name(&container),
            Some((GOOD.to_string(), "mkv-title"))
        );
    }

    /// A container Title that is not a release name renames nothing -
    /// the muxer default, the human title, the path fragment.
    #[test]
    fn an_unconvincing_container_title_is_declined() {
        for t in [
            "video",
            "Sintel",
            "Episode 3",
            "encoded by Handbrake",
            "a/b.mkv",
        ] {
            let f = Facts {
                posted: OBF.into(),
                mkv_title: Some(t.into()),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{t:?}");
        }
        // …and neither does no oracle at all.
        assert_eq!(
            decide_name(&Facts {
                posted: OBF.into(),
                ..Default::default()
            }),
            None
        );
    }

    /// A name that agrees with the one we already have is not news, and
    /// recording it would put a redundant second name on every history
    /// row.
    #[test]
    fn an_answer_that_agrees_with_the_posted_name_is_not_recorded() {
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(GOOD),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(&GOOD.to_ascii_lowercase()),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
    }

    /// A path is not a release name, whichever oracle offered it - and
    /// the srrdb rung does not go through `looks_like_release_name`, so
    /// the refusal has to live in the decision itself. Sanitising it
    /// instead would leave ".. etc Example.Movie.2019-GRP": no longer an
    /// escape, but a hidden dotfile made out of a string that was never
    /// a name.
    #[test]
    fn an_oracle_cannot_hand_back_a_path() {
        for bad in [
            "../../etc/Example.Movie.2019-GRP",
            "..\\..\\Example.Movie.2019-GRP",
            ".hidden.Movie.2019.1080p-GRP",
            "/absolute/Example.Movie.2019-GRP",
        ] {
            let f = Facts {
                posted: OBF.into(),
                srr: srr(bad),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{bad}");
            let f = Facts {
                posted: OBF.into(),
                mkv_title: Some(bad.into()),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{bad}");
        }
    }

    /// The two disk readers. Both run on a finished download's own
    /// directory, so what matters is that they answer on a real one and
    /// stay silent - never panic, never stall - on everything else.
    ///
    /// Gated with its four callers: this crate's own default feature set
    /// has no `indexer` in it (nzbfast forwards to it), so without the
    /// gate a plain `cargo check -p nzbfast-core` reports it dead.
    #[cfg(feature = "indexer")]
    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-ident-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn par_sidecar_reads_a_real_set_and_shrugs_at_everything_else() {
        // The same checked-in par2cmdline output nzbkit's parser tests
        // use, so the two cannot drift.
        const MAIN: &[u8] = include_bytes!("../../nzbkit-base/tests/fixtures/par2/testset.par2");
        let d = tmpdir("par");
        assert!(
            par_sidecar(&d).is_none(),
            "an empty directory has no sidecar"
        );
        std::fs::write(d.join("notes.txt"), b"not a par2").unwrap();
        std::fs::write(d.join("broken.par2"), b"PAR2\0PKTnonsense").unwrap();
        assert!(par_sidecar(&d).is_none(), "garbage must not parse as a set");
        std::fs::write(d.join("testset.par2"), MAIN).unwrap();
        let sc = par_sidecar(&d).unwrap();
        assert_eq!(sc.pairs.len(), 1, "{:?}", sc.pairs);
        assert_eq!(sc.pairs[0].1, "beta.bin");
        assert_eq!(sc.pairs[0].0.len(), 32);
        // The Recovery Set ID - the strong proving key the claims
        // layer records - comes out as 32 lowercase hex chars.
        assert_eq!(sc.set_id.len(), 32);
        assert!(sc.set_id.chars().all(|c| c.is_ascii_hexdigit()));
        // A directory that does not exist is not an error worth having.
        assert!(par_sidecar(&d.join("gone")).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A minimal but well-formed PAR2 index: a Main packet listing one
    /// id per member, a FileDesc for each (declared past
    /// `member_hash16k`'s 16 KiB floor, so every one of them counts),
    /// and a Creator packet of `pad` bytes. The pad is what sets the
    /// FILE size independently of how many members the set describes,
    /// which is how these fixtures choose their sort order.
    #[cfg(feature = "indexer")]
    fn par2_index(set: u8, members: &[&str], pad: usize) -> Vec<u8> {
        let m: Vec<(&str, u8)> = members
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, set ^ (i as u8) ^ 0x80))
            .collect();
        par2_index_hashed(set, &m, pad)
    }

    /// The candidates are sorted by size, and a subtitle pack's index
    /// plus three of its own volumes are all smaller than the release's
    /// index. A fixed window over the first few therefore excluded the
    /// only set worth having and answered with the ancillary one - whose
    /// fingerprint would then be filed as this download's identity.
    #[cfg(feature = "indexer")]
    #[test]
    fn ancillary_sidecars_cannot_crowd_out_the_release_set() {
        let d = tmpdir("parcap");
        // Four small ancillary files, one set, one member each.
        for (i, n) in [
            "subs.par2",
            "subs.vol0+1.par2",
            "subs.vol1+2.par2",
            "subs.vol3+4.par2",
        ]
        .iter()
        .enumerate()
        {
            std::fs::write(d.join(n), par2_index(0x11, &["Subs.srt"], 64 + i * 16)).unwrap();
        }
        // The release's own index: more members, and bigger on disk.
        std::fs::write(
            d.join("release.par2"),
            par2_index(0x22, &["r.rar", "r.r00", "r.r01", "r.r02", "r.r03"], 4096),
        )
        .unwrap();
        let sc = par_sidecar(&d).expect("the release set is present and unique");
        assert_eq!(sc.pairs.len(), 5, "{:?}", sc.pairs);
        assert!(
            sc.pairs.iter().any(|(_, n)| n == "r.rar"),
            "picked the ancillary set: {:?}",
            sc.pairs
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Two sets tie, then a later copy of one of them describes more
    /// members. That is a unique winner, not an ambiguity - the tie the
    /// earlier copy raised no longer stands.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_tie_broken_by_a_fuller_copy_still_answers() {
        let d = tmpdir("partie");
        // A and B tie at two members each...
        std::fs::write(d.join("a.par2"), par2_index(0x31, &["a.rar", "a.r00"], 8)).unwrap();
        std::fs::write(d.join("b.par2"), par2_index(0x41, &["b.rar", "b.r00"], 64)).unwrap();
        // ...until a fuller copy of A turns up describing four.
        std::fs::write(
            d.join("a.vol0+2.par2"),
            par2_index(0x31, &["a.rar", "a.r00", "a.r01", "a.r02"], 512),
        )
        .unwrap();
        let sc = par_sidecar(&d).expect("A covers four members and B two");
        assert_eq!(sc.pairs.len(), 4, "{:?}", sc.pairs);
        assert!(
            sc.pairs.iter().all(|(_, n)| n.starts_with("a.")),
            "{:?}",
            sc.pairs
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The other direction: a genuine tie between two DIFFERENT sets is
    /// still ambiguous, and a wrong identity is worse than none.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_real_tie_between_two_sets_is_still_declined() {
        let d = tmpdir("parambig");
        std::fs::write(d.join("a.par2"), par2_index(0x51, &["a.rar", "a.r00"], 8)).unwrap();
        std::fs::write(d.join("b.par2"), par2_index(0x61, &["b.rar", "b.r00"], 64)).unwrap();
        // A second copy of A that adds nothing does not break the tie.
        std::fs::write(
            d.join("a.vol0+2.par2"),
            par2_index(0x51, &["a.rar", "a.r00"], 512),
        )
        .unwrap();
        assert!(par_sidecar(&d).is_none(), "two sets at two members each");
        let _ = std::fs::remove_dir_all(&d);
    }

    // `container_title` composed with `smart::main_video` - the pair
    // `serve::naming` writes - is pinned in
    // `crates/nzbfast-unpack/src/smart/container_title_tests.rs`. It moved
    // there with the crate-split step 2 cut: `smart` is a layer above
    // this crate, so a test here can no longer reach half of what that
    // property is about. What stays below is the half that is purely
    // this module's.

    #[test]
    fn xrel_is_only_asked_when_it_could_help() {
        // A tagger-group release with no id: the case this exists for.
        assert_eq!(
            xrel_query("Supergirl.2026.1080P.WEB.H264-POKE", "").as_deref(),
            Some("Supergirl 2026")
        );
        // We already know the id.
        assert_eq!(
            xrel_query("Supergirl.2026.1080P.WEB.H264-POKE", "tt8814476"),
            None
        );
        // No group tag: not a release xREL indexes.
        assert_eq!(xrel_query("Supergirl 2026 1080p", ""), None);
        // Nothing to search with.
        assert_eq!(xrel_query(OBF, ""), None);
        assert_eq!(xrel_query("", ""), None);
        // A yearless release still asks, with what it has.
        assert_eq!(
            xrel_query("Some.Show.S01E02.1080p.WEB.h264-POKE", "").as_deref(),
            Some("Some Show")
        );
    }
}
