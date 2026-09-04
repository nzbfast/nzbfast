//! Failure diagnostics: loss classification, the failure snapshot, unsupported-archive detection and the disk-unpack fallback tests.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;

/// Lines of console output a failed job keeps for its history entry, and
/// the byte ceiling that keeps history.json from growing without bound.
///
/// A job that lost every file prints one `⚠` line per file, so the line
/// budget has to clear a full set (the 31 Jul report was 94) and still
/// leave room for the per-server table and the diagnostics footer under
/// it. The LAST lines are the ones kept: a failure block ends with its
/// verdict.
pub(crate) const FAIL_DETAIL_LINES: usize = 160;
pub(crate) const FAIL_DETAIL_BYTES: usize = 24 * 1024;

/// This job's console output since `mark`, as the block a failed history
/// entry carries.
///
/// The one-line `fail_message` is a verdict; this is the evidence for it,
/// and until now it existed only in a memory-only 2000-line ring that a
/// restart wipes - which is exactly what happened to the 31 Jul job whose
/// diagnosis had to be reconstructed by re-probing the servers by hand.
pub fn fail_detail_snapshot(mark: u64) -> String {
    let lines = nzbkit::logtee::since(mark, FAIL_DETAIL_LINES);
    if lines.is_empty() {
        return String::new();
    }
    let mut out = lines.join("\n");
    if out.len() > FAIL_DETAIL_BYTES {
        // Truncate from the FRONT on a line boundary, keeping the tail:
        // the verdict and the server table are the last things printed.
        // Walk forward to a char boundary FIRST. `out.len() -
        // FAIL_DETAIL_BYTES` is a byte offset, and these lines are dense
        // with multi-byte characters - the census prints `⚠` per short
        // file, `print_failure_diagnostics` prints `·` separators, and
        // logtee substitutes U+FFFD for any non-UTF-8 byte a child
        // process emitted. Slicing `out[cut..]` on a continuation byte
        // panics, and the lane supervisor turns that panic into
        // "post-processing crashed (internal error)", which REPLACES the
        // real verdict, drops the evidence this function exists to keep,
        // and - because `fail_kind` classifies on the message opening -
        // relabels a MissingArticles/Transport failure as Local, so the
        // automatic retry never arms.
        let mut cut = out.len() - FAIL_DETAIL_BYTES;
        while cut < out.len() && !out.is_char_boundary(cut) {
            cut += 1;
        }
        let cut = out[cut..].find('\n').map_or(out.len(), |i| cut + i + 1);
        out = format!("[…earlier lines dropped…]\n{}", &out[cut..]);
    }
    out
}

/// Tag a job-failure message with the build that produced it. Failure
/// messages travel: history screenshots, Reddit posts, *arr logs - and
/// they arrive with no other version context. Appended, never prefixed:
/// the daemon's `fail_kind` classifies on the message OPENING.
pub fn with_build(msg: String) -> String {
    format!("{msg} [nzbfast {}]", env!("CARGO_PKG_VERSION"))
}

/// The block a bug report should contain, printed once when a job fails:
/// build, platform, and a per-server table that is deliberately
/// ANONYMOUS - level/connections/TLS/retention/outcome, never hostnames
/// or accounts, because these logs get pasted on public forums.
pub fn print_failure_diagnostics(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
) {
    println!(
        "diagnostics (safe to include in a bug report): nzbfast {} · {} {} · {} cores · {} GB RAM",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        // cpu-workers-gate: a diagnostic REPORTING what the machine has.
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        nzbkit::mem::physical_ram().map_or(0, |b| b / 1_000_000_000),
    );
    for (i, ((s, cfg), st)) in servers.iter().zip(stats).enumerate() {
        let retention = if s.retention_days == 0 {
            "unlimited".to_string()
        } else {
            format!("{}d", s.retention_days)
        };
        let outcome = if st.ever_connected {
            format!(
                "served {:.1} MB ({} connects, {} reconnects){}",
                st.bytes as f64 / 1e6,
                st.connects,
                st.reconnects,
                // A3: the bug-report block is where someone reading a
                // failed job first looks, and "served 4.2 GB" alone hides
                // the single most misleading thing a run can do - lose a
                // server half way and keep counting the rest as unanimous.
                if st.left_mid_run {
                    " then LEFT THE RUN with work outstanding"
                } else {
                    ""
                }
            )
        } else {
            "NO USABLE CONNECTION for the entire run".to_string()
        };
        println!(
            "  server {}: level {} · {} conns · tls={} · retention {} · {}",
            i + 1,
            s.level,
            cfg.connections,
            s.tls,
            retention,
            outcome
        );
    }
}

/// Which of the two failures behind one `decode/write error` counter
/// actually happened, as a value rather than as the opening words of a
/// sentence.
///
/// The two share `derrs` and have OPPOSITE remedies, so
/// [`incomplete_reason`] has to tell them apart to pick a verdict: a
/// corrupt article is the SERVER's copy failing its own yEnc CRC, where
/// free space and permissions are irrelevant and a re-fetch from
/// another provider is the fix, while a write fault is this machine and
/// the folder is where the evidence is. That choice reaches the user as
/// `fail_hint` (`corrupt`) and therefore as `fail_action` (`retry`
/// against `path`).
///
/// Until 26 Aug 2026 it was decided by `sample.starts_with("decode
/// error")` over a string, and both writers - in
/// `crates/nzbfast-engine/src/get/workers.rs` - already KNEW which one it was
/// at the moment they wrote it. TODO 307 item 1 named that as an
/// instance of the tree's string-classification class and left it for
/// its own claim, this one, beside `repair::sidefetch`'s. What the
/// string cost is what any of them costs: the opening is prose, an
/// edited word moves a machine's disk fault into "the copies on the
/// server are corrupt" with nothing anywhere going red, and the two
/// producers are in a different module from the reader that parses
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeFault {
    /// The server handed us bytes that failed their own yEnc CRC or
    /// length check. Every article arrived; the copies are corrupt.
    Corrupt,
    /// The bytes decoded and this machine could not store them - a full
    /// volume, a permission, a share gone read-only.
    Write,
}

/// The first decode-or-write error of a run, paired with the producer's
/// own verdict about which it was. See [`DecodeFault`].
///
/// The pairing is set at ONE `get_or_insert_with`, in the same
/// statement as the text, so the two cannot drift apart: a fault
/// recorded beside a message it does not describe is the same defect
/// the string test had, just harder to see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeSample {
    pub fault: DecodeFault,
    /// The sentence itself - the OS's own words in the OS's own
    /// language, quoted into the verdict's `(first error: ...)` tail
    /// and read back by `disk_full_failure` for the full-volume arm.
    pub text: String,
}

/// The run's first decode-or-write error, shared between the decode
/// workers that record it and the tail that reads it into
/// [`LossCauses`]. First writer wins.
pub type DecodeSampleCell = Arc<std::sync::Mutex<Option<DecodeSample>>>;

impl DecodeSample {
    pub fn corrupt(text: String) -> Self {
        DecodeSample {
            fault: DecodeFault::Corrupt,
            text,
        }
    }

    pub fn write(text: String) -> Self {
        DecodeSample {
            fault: DecodeFault::Write,
            text,
        }
    }
}

/// Why a download did not come out whole - as a sentence whose OPENING
/// says which of the two it was, because the daemon's policies read it.
///
/// A missing segment is the post's problem: it earns an auto-retry (
/// propagation often fills the gap) and, with failure-link reporting on,
/// it is what the indexer wants to hear about. A decode/write error with
/// nothing missing is OUR machine's problem - a full disk, a permission
/// denied, a bad sector. Folding the two into one "download incomplete:
/// N file(s) with missing segments, M decode/write errors" told the
/// indexer a healthy release was dead and armed a retry straight back
/// onto the same full disk. Both counts still appear when both happened;
/// only the leading clause decides.
///
/// Known causes ride along AFTER the classifying clause (the daemon's
/// `fail_kind` and the tests pin the opening, so additions must append):
/// segments excluded by a configured `retention_days`, transport-error
/// losses with the first error quoted, servers that never held a usable
/// connection for the whole run, servers that served and then left it
/// part-way through, and repair's block arithmetic. All of
/// it turns "missing segments" from a dead-post verdict into something
/// the user can act on - the Hblife report ("every file failed, SAB got
/// them fine") was undiagnosable precisely because the summary never
/// said WHY the pool gave up on an article.
///
/// One opening is special: when NOT ONE loss was a server saying 430
/// (all transport, or transport plus retention exclusions), the message
/// opens "download failed on connection errors" instead - the daemon
/// classifies that `FailKind::Transport`, which still auto-retries but
/// never reports the post to an indexer as dead. A flaky provider under
/// load used to file takedown reports for healthy releases.
pub struct LossCauses<'a> {
    // Sweep 8, M7: the four cause counters below are PAYLOAD-ONLY, and
    // their recovery-side twins follow them. They used to be flat
    // totals over every slot alike while every gate here read them as
    // statements about the payload, so one 430 on an irrelevant `.par2`
    // article suppressed `all_transport` and had a release whose
    // payload died entirely in transport reported as missing/gone - to
    // the user and to the indexer - and one transport failure on a
    // recovery article suppressed the wholly-gone verdict for a post
    // that was genuinely gone. The split is taken at collection, where
    // the article's slot is still in hand (`get::workers::CauseSplit`).
    /// Payload segments where every live server was asked and said
    /// 430/423.
    pub missing_430: u64,
    /// Of those, segments where at least one refusing server SAID the
    /// article was removed (Giganews's documented 451, or refusal text
    /// naming a takedown) rather than merely not found. Wording only -
    /// a takedown-flavoured refusal is still exactly one refusal for
    /// every count and verdict above, and 0 is no evidence either way
    /// (most backbones never name the reason).
    pub takedown_430: u64,
    /// Of those, segments the pool wrote off while the fleet was SHORT:
    /// a server that had been serving went out before the article ever
    /// reached it, so the survivors' 430s read as unanimous over a
    /// quorum that was no longer whole (`pool::MissingCause::Unasked`).
    ///
    /// Rides its own counter for exactly the reason `takedown_430`
    /// does, and stays inside `missing_430` for every count and verdict
    /// above: the article IS still absent from every server that
    /// answered, so moving it out would change what the repair planner
    /// and every gate here read. What it buys is the WORDING - see
    /// [`LossCauses::asked_430`] and [`unasked_clause`]. The standing
    /// rule is the memory topic `nzbfast-retry-propagation-trap`: say
    /// it in the message, keep the classification.
    ///
    /// PAYLOAD-ONLY WITH NO RECOVERY TWIN, unlike every counter around
    /// it, and that is a decision rather than an omission. The
    /// recovery-side clauses claim no unanimity - "were lost as well,
    /// so there was less parity available to repair with" is true of an
    /// unasked parity segment exactly as it is of a refused one - so a
    /// twin would carry a distinction no sentence spends and would cost
    /// a field in every literal that builds this struct. The clauses
    /// that DO claim "every server" are all payload clauses, and they
    /// are the ones this counter corrects.
    pub unasked_430: u64,
    /// Never requested: outside every server's configured retention.
    pub retention_excluded: u64,
    /// Payload segments lost to transport errors (timeouts, resets,
    /// exhausted retries).
    pub transport_failed: u64,
    /// The recovery-side share of each counter above. Repair context,
    /// never a payload verdict: nothing in the classification below may
    /// read these, and the summary reports them as what they are - a
    /// reason the parity could not heal the payload, not evidence about
    /// the payload itself.
    pub missing_430_recovery: u64,
    pub takedown_430_recovery: u64,
    pub retention_excluded_recovery: u64,
    pub transport_failed_recovery: u64,
    /// Recovery (PAR2) segments the post carries, as the DENOMINATOR the
    /// four counters above have never had. Without it a recovery loss is
    /// a bare number: 135 lost segments is a scratch on a 17,000-segment
    /// set and the whole of a 200-segment one, and only the second of
    /// those is a reason the job died. 0 = the caller has no per-slot
    /// recovery accounting, which stands the verdict below down entirely
    /// (the conservative direction: no denominator, no claim).
    pub recovery_segments: u64,
    /// The repair ladder's terminal verdict about the recovery set
    /// itself: this source will not serve it, whatever the download-time
    /// counters above say.
    ///
    /// SEAM for TODO 282 item 4, which owns `repair.rs` and the measured
    /// yield gate behind that verdict; today nothing sets it and the
    /// counters above are the only evidence this module has. It is here
    /// rather than in item 4's own change because the ORDERING is this
    /// module's business - see [`recovery_is_the_casualty`] - and a
    /// verdict landing later must not have to re-argue where it goes.
    ///
    /// The incident this whole rung exists for is exactly the case only
    /// this field can carry, and the reason is structural rather than
    /// incidental. `get::plan` NEVER puts a named `Par2Volume` in the
    /// main plan - the whole one-pass design is that parity is fetched
    /// only if damage turns up - so on a conventionally named recovery
    /// set every counter above is unreachable BY CONSTRUCTION, whatever
    /// the provider does. The 1206 article failures that killed the
    /// 24 Aug job all happened in the repair-side fetch, which writes
    /// volume files directly and has no `FileSlot` to charge.
    ///
    /// Reproduced here on 24 Aug 2026 at test scale (a 2 MB payload, a
    /// 10% named par2 set, every volume article answered 430): the run
    /// logged `fetched 0.0 MB of recovery data (12 article failures)`
    /// twice and reached this module with all four recovery counters at
    /// zero. So the counters cover the OBFUSCATED shape, where the
    /// volumes are downloaded before anything knows what they are, and
    /// this field covers the common one.
    pub recovery_unobtainable: bool,
    /// First transport error, verbatim.
    pub transport_sample: Option<String>,
    /// First decode/write error, verbatim, with the producer's own
    /// verdict about which of the two it was. See [`DecodeSample`].
    pub decode_sample: Option<DecodeSample>,
    /// Decode/write errors charged to RECOVERY slots. Excluded from
    /// `derrs` on purpose - they are not payload damage - but they are
    /// still damage, and a journal-resume retry can fetch clean parity
    /// from another provider (Codex sweep 5, M6).
    pub recovery_errs: u64,
    /// Servers with no usable connection at any point in the run.
    pub dead_servers: &'a [String],
    /// Servers that connected and served and then LEFT before the run
    /// ended - a permanent refusal, a spent block or quota, the outage
    /// budget blown, the connect-attempt cap.
    ///
    /// The quorum shrank part-way through and nothing said so: the pool
    /// decides terminal outcomes against `live_mask` (alive NOW), so
    /// once a server's last worker retires, the survivors' 430s on the
    /// segments it alone still had to answer for read as unanimous.
    /// `dead_servers` could not carry this - it keys on
    /// `!ever_connected`, which is FALSE for a server that worked for
    /// ten minutes first. Consequences of the silence: `post_gone`
    /// firing on a healthy post, and `missing_articles_proven_stale`
    /// seeing no ambiguity and suppressing the one automatic retry -
    /// which also makes the failure final (error-detection audit 20
    /// Aug, A3).
    pub left_servers: &'a [String],
    /// PAR2 recovery slots the NZB carries. Zero means the post has no
    /// parity at all, so a confirmed-missing segment can never be
    /// reconstructed and no amount of retrying changes that.
    pub par2_slots: usize,
    /// The stall watchdog aborted the tail: no decode progress for its
    /// whole window while segments were still outstanding.
    ///
    /// This one outranks every count below it, because when it is set
    /// the counts describe a run that STOPPED rather than a post that is
    /// short. The abandoned segments were never asked and refused - most
    /// were never asked at all - so they arrive here as neither
    /// `missing_430` nor `transport_failed`, and the ordinary opening
    /// then reports the most alarming thing it can say ("N file(s) with
    /// missing segments") about a release nobody has shown to be
    /// missing anything. Observed 31 Jul on a 94-file post: the pool
    /// wedged with 8851 segments outstanding, and the history entry read
    /// exactly like a dead release.
    pub stalled: bool,
    /// Segments that never arrived - terminally missing, or still
    /// unresolved when the run gave up - and how many the job asked for
    /// in all. A file count cannot separate "short one segment each,
    /// one repair away" from "short every segment, the post is gone";
    /// these can. Both 0 when a caller has no per-slot accounting, which
    /// suppresses every clause that reads them.
    pub missing_segments: u64,
    pub total_segments: u64,
    /// Raw bytes the servers actually delivered. Zero is the single most
    /// diagnostic number a failed job has: it says the run never got
    /// anything, as opposed to getting most of it and falling short.
    pub bytes_arrived: u64,
    /// Distinct backbones behind the servers that took part. Five
    /// resellers of one backbone are ONE opinion, and "no server had it"
    /// otherwise reads like five independent votes.
    pub backbones: &'a [String],
    /// Age of the youngest article in the post, days. 0 when the NZB
    /// carries no usable date - see `GONE_MIN_AGE_DAYS`.
    pub post_age_days: u32,
}

impl LossCauses<'_> {
    /// Recovery (PAR2) segments this run cannot repair from: absent for
    /// any reason, or arrived and failed their own checks.
    ///
    /// Deliberately WIDER than the `rec_lost` the trailing recovery
    /// clause quotes, which counts absence only. Parity that decoded
    /// wrong is parity we do not have, and the question this figure
    /// answers - is the recovery set the casualty - does not care which
    /// way it was lost. The two are not merged because the trailing
    /// clause's sentence ("were lost as well") is about absence and its
    /// count is pinned by
    /// `a_recovery_articles_failure_never_decides_the_payloads_verdict`.
    fn recovery_unusable(&self) -> u64 {
        self.missing_430_recovery
            + self.transport_failed_recovery
            + self.retention_excluded_recovery
            + self.recovery_errs
    }

    /// Payload refusals a WHOLE fleet gave: `missing_430` less the share
    /// written off after a participating server had already gone out.
    ///
    /// Every clause in [`incomplete_verdict`] that says "confirmed
    /// missing by every server", or counts the backbones behind that
    /// verdict, has to spend THIS figure and not `missing_430`. The two
    /// were the same number until `MissingCause::Unasked` existed, and
    /// the sentence they produce is the one the user acts on: "every
    /// server said this article is gone" sends them looking for another
    /// copy of the release, where "our own fleet shrank" sends them to
    /// the server that stopped, or simply to try again later. Reporting
    /// a loss our fleet caused in the first set of words is the defect
    /// the participation mask in `nzbkit::pool::gates` was built to
    /// make visible.
    ///
    /// Saturating rather than a plain subtraction: `unasked_430` is a
    /// SHARE of `missing_430` by construction (`get::workers`
    /// `note_missing_cause` charges both from one arm), so the two can
    /// only disagree if a caller builds this struct by hand, and a
    /// panic in the failure-summary path would replace a bad sentence
    /// with no job report at all.
    fn asked_430(&self) -> u64 {
        self.missing_430.saturating_sub(self.unasked_430)
    }
}

/// How old a post must be before "every article 430" may be called DEAD
/// rather than "not here yet".
///
/// Both look identical from the pool's side. Propagation across the
/// backbones is normally minutes and occasionally hours; three days is
/// far outside that and still well inside the window where a retry could
/// plausibly have helped, so nothing that a retry would have fixed is
/// classified away. Below it (and for a dateless NZB, which reads as age
/// 0) the classic transient opening stands and the automatic retry runs.
pub const GONE_MIN_AGE_DAYS: u32 = 3;

/// The share of a post's recovery set that has to be gone before the
/// parity is called the casualty rather than the payload.
///
/// More than half, and deliberately blunt: this decides one CLAUSE of
/// one sentence, and the alternative to a blunt threshold here is the
/// message that sent a user looking at articles, then at par2cmdline,
/// for a job whose payload was 99.2% intact.
const RECOVERY_DEAD_NUM: u64 = 1;
const RECOVERY_DEAD_DEN: u64 = 2;

/// How short the payload may be and still be described as the survivor.
///
/// A post that carries parity at all carries it in the region of 10% of
/// the payload (the 24 Aug incident's was 255 blocks against 2550-odd,
/// and 10% is the scene norm), so a payload short by under a twentieth
/// of its segments is inside what an OBTAINABLE recovery set would have
/// covered. That is what licenses the clause to say "not the payload".
/// It is not a promise that the repair would have succeeded - nothing
/// here knows the block geometry - and the sentence does not make one.
const PAYLOAD_INTACT_DEN: u64 = 20;

/// Which of the two halves of a post actually died: the payload, or the
/// recovery set that was supposed to fix it.
///
/// A RUNG of the opening precedence in [`incomplete_reason`], not a
/// special case bolted on the side, and its position in that ordering is
/// the whole of the design:
///
/// * `stalled` outranks it, for the reason the propagation-trap note
///   established - a stalled pool never asked for most of what it is
///   now short of, so no count it collected is evidence about anything,
///   the recovery counts included.
/// * `size_header_lies` and `post_gone` outrank it because both are
///   POSITIVE evidence about the payload: nothing was lost at all, or
///   every article of every file was. Neither leaves a gap for parity
///   to close, so naming the parity would be beside the point.
/// * `all_transport` outranks it because it is a statement about THIS
///   machine's link, and `fail_kind` maps its opening to `Transport` -
///   the one classification that never reports a release to an indexer
///   as dead. A flaky provider that failed the parity fetch too must
///   not talk its way out of that.
///
/// Everything below it is the plain missing-articles opening, which is
/// the one this rung exists to displace.
fn recovery_is_the_casualty(
    causes: &LossCauses,
    derrs: u64,
    post_gone: bool,
    size_header_lies: bool,
    all_transport: bool,
) -> bool {
    if post_gone || size_header_lies || all_transport {
        return false;
    }
    let mostly_gone = causes.recovery_segments > 0
        && causes.recovery_unusable() * RECOVERY_DEAD_DEN
            > causes.recovery_segments * RECOVERY_DEAD_NUM;
    if !(mostly_gone || causes.recovery_unobtainable) {
        return false;
    }
    // The comparative claim needs its other half PROVEN, not assumed.
    // Both sides can be short at once, and a run that lost a third of
    // its payload has no business being told the payload was fine.
    //
    // `derrs` counts with `missing_segments` here, for the reason the
    // `size_header_lies` block below spells out: a decode or write
    // error leaves `missing_segments` at zero while the failed
    // article's bytes ARE a real gap in the payload. Both counters are
    // payload-only, so the sum is the payload's whole loss - and a
    // damaged payload is exactly what sends the repair ladder after
    // volumes it then cannot fetch, so `recovery_unobtainable` beside a
    // pile of decode errors is a natural pairing rather than a contrived
    // one. Counted rather than a flat `derrs == 0` test: one corrupt
    // article out of 17130 should no more stand the clause down than one
    // absent article does, and the same twentieth governs both kinds of
    // gap.
    causes.total_segments > 0
        && causes
            .missing_segments
            .saturating_add(derrs)
            .saturating_mul(PAYLOAD_INTACT_DEN)
            <= causes.total_segments
}

/// What the fleet's own shrinkage cost this run, as the clause that
/// tells the `left_servers` line what it was FOR.
///
/// `left_servers` names the server that served and then stopped;
/// `unasked_430` is the bill. Until both are said the pair is two
/// unrelated warnings - one about a provider, one about a post - and a
/// reader has no way to join them, which is how a loss our own fleet
/// caused went out reading as a verdict about the POST. Placed directly
/// after that line for the same reason, so the two arrive as one story.
///
/// SELF-CONTAINED on purpose, rather than "N of those": the two facts
/// come from different latches and one can fire without the other.
/// `note_server_dark` skips the `left_mid_run` latch when the run is
/// already aborted or draining, so a torn-down run can reach a terminal
/// `Unasked` with `left_servers` empty. Rare, and a clause that reads as
/// a dangling reference in exactly the case nothing else explains is the
/// wrong half to save two words on.
///
/// IT NEVER SUPPRESSES THE REFUSAL CLAUSES, and that is the whole
/// arithmetic. A run can be BOTH at once, and the first cut of the STALL
/// message is the standing warning: it reassured a user that the failure
/// was "not evidence that anything is missing" about a release four
/// providers had just called short 2031 times. So the refusal clauses
/// keep saying what a whole fleet refused - `asked_430`, not
/// `missing_430` - and this one says what nobody was asked for. The two
/// figures sum to `missing_430`, so neither has to walk the other back.
///
/// An empty string when there is nothing to report, so the call site is
/// one line: this function's own comment is long, and
/// [`incomplete_verdict`] is inside twenty lines of the 500-line
/// function ceiling (`tools/size-gate.py`).
fn unasked_clause(causes: &LossCauses) -> String {
    if causes.unasked_430 == 0 {
        return String::new();
    }
    format!(
        "; {} segment(s) were written off while the fleet was short - a server that \
         had been serving went out before those articles reached it, so no server \
         that could still have answered was asked for them, and another attempt once \
         that server is back may well find them",
        causes.unasked_430
    )
}

/// [`incomplete_verdict`]'s sentence alone.
///
/// TEST-ONLY since TODO 307 item 1's job-level carry, and that is the
/// whole story of this function: production now takes the kind and the
/// words together, because throwing the kind away here is what forced
/// the daemon to rebuild it from the prose. Ninety-nine assertions read
/// the sentence and nothing else, so the wrapper stays for them - as a
/// wrapper, never as a second copy of the branch ladder, which would be
/// the exact "second thing to keep in step" this item exists to remove.
#[cfg(any(test, feature = "test-support"))]
pub fn incomplete_reason(incomplete: usize, derrs: u64, causes: &LossCauses) -> String {
    incomplete_verdict(incomplete, derrs, causes).1
}

// `repair::extpar2`'s until the crate-split prep (step 1 of
// research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md). It is a string
// formatter over a count and nothing else, and `unpack` composes the
// same sentence for the nested-set pass - so leaving it in the repair
// ladder was the one edge that made those two modules need each other.
// `repair` re-exports it.

/// The "and adoption already found some of it" half of an unrepairable
/// verdict, shared by every surface that prints one.
///
/// `RepairReport::blocks_adopted` only reaches a caller through
/// `RepairStatus::Repaired`, so until 29 Aug 2026 a donation that
/// bridged SOME of the damage and still came up short left no trace on
/// any surface: the shortfall lines named `needed` and `have` and
/// nothing else. That is not a cosmetic gap. A bench round on 28 Aug
/// 2026 read `grep -c "block(s) adopted from" == 0` over a whole daemon
/// log and recorded "adoption bridged nothing" as an open question,
/// when the arithmetic in that same log (290 blocks bad at verify, 268
/// needed at the native verdict) says adoption had in fact found 22 of
/// them. The count is what tells a partial donation from no donation,
/// and it belongs wherever the shortfall is reported.
///
/// IT DOES NOT SAY WHERE, and until 31 Aug 2026 it did: the sentence
/// read "in files outside the recovery set", which is false on two of
/// the three paths that feed the count. `repair_dir_set_inner` fills
/// ONE `adopted` map from three writers and then reports its length -
/// `adopt::adopt_blocks` (extra files in the repair directory and the
/// §293 donor dirs, genuinely outside the set), `adopt::harvest_in_set`
/// (one member of the set standing in for a missing slice of another,
/// INSIDE it by definition), and the last-resort escalation's
/// `adopt::sliding_scan` over identified damaged targets, which are the
/// set's own declared members. On the two in-set paths the sentence
/// told the user the opposite of what had happened. Observed live on
/// `e2e_norar::twin_adopt::a_claimed_twin_donates_the_shared_head_it_declares_twice`,
/// which logs "adoption already found 10 of them in files outside the
/// recovery set" two lines above "10 block(s) adopted from
/// Twin.Beta.vob" - a file the set declares. The escalation predates
/// the clause by five weeks (0b04420b7, 21 Jul 2026, against c8aa87e78,
/// 28 Aug), so the claim was never true across all paths; it was
/// written from the donor path it was measured on.
///
/// "already on disk" is what survives, and it is not a retreat to
/// vagueness: it is true on all three paths, it pairs with the
/// `only {have} recovery block(s) on disk` half of the same sentence,
/// and it carries the contrast the original was reaching for - these
/// blocks cost no fetch and no solve, they were simply already there.
///
/// WHY THE SOURCES ARE NOT PLUMBED THROUGH INSTEAD, so this is not
/// reopened. `RepairReport::adopted_from` already holds the donor
/// names, and threading them onto `RepairStatus::Unrepairable` beside
/// the count is perhaps twenty sites of mechanical work: the two
/// construction sites in `par2repair`, the five callers of this
/// function, and the handful of matches that destructure the variant
/// rather than taking `..`. It was considered and declined on two
/// grounds. FIRST, nothing downstream of this line acts on the answer.
/// This is a FAILURE line - the repair did not happen and nothing was
/// written - and the verdict ("you do not have enough recovery data")
/// and the remedy (more parity, or the missing articles) are the same
/// whichever file the found blocks came out of. What changes the
/// reading is the ARITHMETIC, which is why the count is here at all.
/// SECOND, and this is the one that decided it: a per-source claim has
/// to be re-derived every time an adoption path is added, and failing
/// to do that is exactly how this defect was born. A count is true of
/// a fourth writer the day it lands; a location is not. If the names
/// are ever wanted here, take them from `adopted_from` rather than
/// classifying inside-versus-outside at the construction sites - the
/// success line already spells them that way ("N block(s) adopted from
/// <names>"), and one spelling is the whole point.
///
/// Empty when nothing was adopted, so the everyday line is unchanged.
pub fn adopted_clause(adopted: usize) -> String {
    if adopted == 0 {
        String::new()
    } else {
        format!(" (adoption already found {adopted} of them in files already on disk)")
    }
}

/// The unobtainable-parity phrase, shared by the opening verdict in
/// [`incomplete_verdict`] and the detail clause in
/// [`append_evidence_clauses`] - one string so the two can never
/// disagree about the words `fail_kind` and the reader see.
///
/// Written once outside the `recovery_casualty` arm rather than inside
/// it, because the rung can stand DOWN with the flag still set - a
/// payload short by more than a twentieth loses the comparative claim,
/// not the repair ladder's verdict - and the CLAUSE is then the only
/// surface that verdict has. Every counter in `rec_lost` is zero by
/// construction on a conventionally named recovery set (`get::plan`
/// gives a named `Par2Volume` no slot), so nothing else would carry it.
///
/// It sat at function scope until the 2 Sep 2026 headroom split put the
/// two readers in two functions; module scope is the same single copy,
/// one level out.
const UNOBTAINABLE: &str = "the PAR2 recovery volumes this repair needed could not be fetched from \
     any server that has the post";

/// The four facts the opening verdict turned on. Each one suppresses the
/// detail clause that would otherwise repeat it, so they cross the seam
/// together - a bundle rather than four adjacent booleans, which is the
/// argument order nobody can read at a call site.
struct VerdictFlags {
    post_gone: bool,
    size_header_lies: bool,
    all_transport: bool,
    recovery_casualty: bool,
}

/// Append every evidence clause the counters justify to an opening
/// verdict already chosen.
///
/// Moved verbatim out of [`incomplete_verdict`] for the 500-line
/// function ceiling. A clause can never move `fail_kind`, which
/// classifies on the OPENING - which is exactly why the two halves
/// separate cleanly here, and why this one takes the flags read-only.
fn append_evidence_clauses(msg: &mut String, causes: &LossCauses, derrs: u64, f: &VerdictFlags) {
    // Damage is not absence, and the automatic-retry gate has to be
    // able to tell them apart. `missing_articles_proven_stale` reads
    // this message back and suppresses the single automatic retry on
    // an aged post - but "aged" answers only whether PROPAGATION can
    // still help. A corrupt article is bytes that were posted and
    // arrived damaged, and a journal-resume retry re-fetches exactly
    // those, which is the case the opening above was deliberately
    // chosen for ("A corrupt article is exactly the case a
    // journal-resume retry can heal"). Without this clause the gate
    // silently overrode that decision: an aged post whose ONLY fault
    // was damaged payload still opened "download incomplete", still
    // collected the age clause, and lost its retry - and a
    // suppressed retry is also FINAL, so the release was reported
    // dead to the indexer, the FailureLink re-grab ran and a held
    // duplicate was promoted. A phrase rather than a count, matching
    // the two exclusions that already work this way; the count in
    // the opening cannot serve, because it reads "0 decode/write
    // errors" when there are none (Codex sweep 4, M3).
    // Recovery damage counts here as much as payload damage. The
    // census excludes it from `derrs` correctly - it is not a payload
    // failure - but the RETRY question is different: corrupt parity
    // beside a missing payload article is exactly the shape where a
    // fresh copy of that parity repairs the gap, and without this the
    // failure read as pure settled absence and lost its one automatic
    // retry (Codex sweep 5, M6).
    if derrs > 0 || causes.recovery_errs > 0 {
        msg.push_str(
            "; some of that loss is damaged articles rather than absent ones, \
             which a retry can fetch again",
        );
    }
    // The recovery side, as its own sentence and never as evidence
    // (sweep 8, M7). These losses used to be folded into the
    // counters above, where they changed the payload verdict; now
    // they are reported as what they actually are - the reason the
    // parity could not close a gap the payload has. A clause, so it
    // can never move `fail_kind`, which classifies on the opening.
    let rec_lost = causes.missing_430_recovery
        + causes.transport_failed_recovery
        + causes.retention_excluded_recovery;
    // Suppressed when the opening already led with it: the rung
    // above spends the same figures on the headline, and saying them
    // twice in one sentence reads as two separate losses.
    if rec_lost > 0 && !f.recovery_casualty {
        msg.push_str(&format!(
            "; {rec_lost} recovery (PAR2) segment(s) were lost as well, so there \
             was less parity available to repair with than the post carries"
        ));
        // A takedown on the parity is the same hint as one on the
        // payload and belongs in the same sentence: waiting cannot
        // bring the recovery volumes back either.
        if causes.takedown_430_recovery > 0 {
            msg.push_str(&format!(
                " ({} of them reported as removed for a takedown request)",
                causes.takedown_430_recovery
            ));
        }
    } else if causes.takedown_430_recovery > 0 {
        // The takedown flavour survives the suppression above on its
        // own, as its own clause. It is the one fact about a dead
        // recovery set that changes what the user should do next -
        // waiting cannot bring a removed volume back - and the
        // headline says the set is gone, never why.
        msg.push_str(&format!(
            "; {} of those recovery segment(s) were reported as removed for a \
             takedown request, so waiting will not bring the parity back",
            causes.takedown_430_recovery
        ));
    }
    // The seam's half of the same evidence, and it needs its own
    // clause for the reason the census half does not: `rec_lost`
    // counts download-time slots, and a conventionally named
    // recovery set has none, so a stood-down rung would drop the
    // repair ladder's `Unservable` verdict entirely and the user
    // would read the plain "N file(s) with missing segments" with no
    // word about the volume fetch having failed. Suppressed when the
    // rung fired, which already spent it on the headline; joined to
    // the clause above rather than repeating its tail when both have
    // something to say.
    if causes.recovery_unobtainable && !f.recovery_casualty {
        if rec_lost > 0 {
            msg.push_str(&format!("; and {UNOBTAINABLE}"));
        } else {
            msg.push_str(&format!(
                "; {UNOBTAINABLE}, so there was less parity available to repair \
                 with than the post carries"
            ));
        }
    }
    // The segment census, right behind the classifying clause. "94
    // file(s) with missing segments" was the whole story a user got,
    // and it is the same sentence whether one segment or twelve
    // thousand went astray. Suppressed on the `post_gone` opening,
    // which has already said every article of every file was absent.
    if causes.total_segments > 0 && !f.post_gone {
        msg.push_str(&format!(
            "; {} of {} segment(s) never arrived ({:.0} MB did)",
            causes.missing_segments,
            causes.total_segments,
            causes.bytes_arrived as f64 / 1e6
        ));
    }
    // How old the post is, when that is knowable and old enough to
    // settle the question the next two surfaces both raise. Both the
    // armed-retry line and the "what to do" line told Gary (16 Aug)
    // that "posts often finish propagating within the hour" about a
    // post several days old - true in general, and plainly wrong
    // about the post in front of him. The age lived only in the
    // `post_gone` gate above, so the page could not know it.
    //
    // Whole days, floored: a same-day post says nothing here, and a
    // dateless NZB reads as age 0 and is likewise silent, so the
    // classic transient wording stands wherever propagation really
    // could still be the answer. Deliberately a statement of fact
    // and not a verdict - a late backfill can still fill a gap, and
    // the automatic retry stays armed either way (this appends, and
    // `fail_kind` keys on the OPENING). `fail_hint` keys on it
    // verbatim.
    //
    // Only on the plain missing-articles opening. A short post's age
    // says nothing (the bytes were never posted, so no amount of
    // waiting was ever going to help) and a transport failure is
    // ours, not the post's - and both already own a `fail_hint` this
    // clause would otherwise take from them.
    if causes.post_age_days >= 1 && !f.post_gone && !f.size_header_lies && !f.all_transport {
        msg.push_str(&format!(
            "; the post is {} day(s) old, well past the minutes-to-hours \
             that propagation takes",
            causes.post_age_days
        ));
    }
    // No parity in the post: a confirmed-missing segment cannot be
    // rebuilt, so say so plainly. Deliberately a CLAUSE and not its
    // own verdict - an earlier cut made this final and stopped the
    // automatic retry, which broke the case the retry exists for: a
    // freshly posted article 430s on every server until it
    // propagates, and looks identical to one that is gone for good.
    // `post_gone` is the properly-gated version of that verdict (it
    // additionally requires nothing to have arrived and the post to
    // be older than propagation explains), so this stands down when
    // that fired rather than saying the same thing twice.
    if causes.asked_430() > 0 && causes.par2_slots == 0 && !f.post_gone {
        msg.push_str(&format!(
            "; {} segment(s) were confirmed missing by every server AND this post \
             carries no PAR2 recovery data, so nothing can rebuild them. If the \
             post is not brand new (where the servers may simply not have it yet), \
             retrying will not help and another version is the answer",
            causes.asked_430()
        ));
    }
    // The takedown flavour, where a server actually named it. Most
    // backbones answer a plain "no such article" for a takedown and
    // a not-yet-propagated post alike, so this clause only appears
    // when a refusal put "removed" on the record - and then it is
    // the most diagnostic thing the summary can say: the copy was
    // taken down, so waiting cannot help and another version of the
    // release is the answer. Deliberately an appended CLAUSE and
    // never an opening: `fail_kind` classifies on the opening, and
    // a takedown hint must not move the verdict class (a hint,
    // never a gate). The dominant form says so outright; a minority
    // of flagged segments only states the fact.
    if causes.takedown_430 > 0 {
        let (t, m) = (causes.takedown_430, causes.missing_430);
        if t * 2 >= m {
            msg.push_str(&format!(
                "; a server reported {t} of the {m} refused segment(s) as removed \
                 for a takedown request, so this copy was taken down rather than \
                 lost in propagation - another release is the likely answer"
            ));
        } else {
            msg.push_str(&format!(
                "; a server reported {t} segment(s) as removed for a takedown request"
            ));
        }
    }
    if causes.retention_excluded > 0 {
        msg.push_str(&format!(
            "; {} segment(s) were never requested because they are older than every \
             server's configured retention - check retention_days in the server \
             settings (0 = unlimited)",
            causes.retention_excluded
        ));
    }
    if causes.transport_failed > 0 && !f.all_transport {
        msg.push_str(&format!(
            "; {} segment(s) lost to transport/connection errors, not takedowns",
            causes.transport_failed
        ));
    }
    if causes.transport_failed > 0
        && let Some(e) = &causes.transport_sample
    {
        msg.push_str(&format!(" (first error: {e})"));
    }
    if !causes.dead_servers.is_empty() {
        msg.push_str(&format!(
            "; no usable connection to {} for the entire run (unreachable, or it \
             refused the login) - segments only that server carries were counted \
             as missing",
            causes.dead_servers.join(", ")
        ));
    }
    // Its mid-run twin, and deliberately its OWN sentence rather than
    // a second host in the clause above. To the user these are
    // different facts: one server was never any use, the other worked
    // and then stopped, which is what a spent block, an expired
    // account or a takedown-shaped refusal looks like from here, and
    // it is the one they can often fix. To the retry gate they are the
    // same fact - the quorum was short - so the wording carries its
    // own exclusion in `missing_articles_proven_stale`, pinned by
    // `a_server_that_left_mid_run_is_never_proven_stale`.
    if !causes.left_servers.is_empty() {
        msg.push_str(&format!(
            "; {} served for part of the run and then stopped (refused, out of \
             quota, or unreachable for too long) - segments only that server \
             carries were decided without it",
            causes.left_servers.join(", ")
        ));
    }
    // What that departure COST, joined to the line above: see
    // [`unasked_clause`], which is empty when nothing was unasked.
    msg.push_str(&unasked_clause(causes));
    // How many INDEPENDENT opinions the verdict rests on. Only where
    // a server actually said 430: on a transport-only failure nobody
    // gave an opinion about the post at all, and naming the backbones
    // there would dress a provider wobble up as a unanimous verdict.
    if causes.asked_430() > 0 && !causes.backbones.is_empty() {
        msg.push_str(&format!(
            "; asked {} backbone(s): {} (resellers of one backbone answer alike)",
            causes.backbones.len(),
            causes.backbones.join(", ")
        ));
    }
}

/// Why a download did not come out whole - the CLASSIFICATION and the
/// sentence, decided together and returned together.
///
/// TODO 307 item 1's job-level carry. Every opening below was already
/// chosen for the `fail_kind` it would produce - the comments in this
/// function say so at every arm, at length, with the incidents behind
/// them - and the daemon then threw that knowledge away and rebuilt it
/// by `starts_with` over the words. The kind is now stated where it is
/// decided; the words are unchanged, and `failkind::tests::producers`
/// asserts on every row that the two still agree.
pub fn incomplete_verdict(
    incomplete: usize,
    derrs: u64,
    causes: &LossCauses,
) -> (crate::failkind::FailKind, String) {
    use crate::failkind::FailKind;
    if incomplete > 0 {
        // A stall is OUR failure and has to say so, before any count is
        // read as evidence about the post. It opens with the connection
        // errors clause deliberately: `fail_kind` maps that to
        // `Transport`, which is exactly right here - retry freely, and
        // never report the release to an indexer as dead.
        if causes.stalled {
            let mut msg = format!(
                "download failed on connection errors: the connection pool stalled \
                 and the download was cut short with {incomplete} file(s) still \
                 incomplete, {derrs} decode/write errors."
            );
            // Do NOT claim the post is healthy when servers have said
            // otherwise. A run can both stall AND collect real 430s, and
            // the first version of this message told the user "not
            // evidence that anything is missing" about a release where
            // four providers had said exactly that, thousands of times.
            match causes.asked_430() {
                0 => msg.push_str(
                    " No server said any article was missing, so this is a fault on \
                     THIS machine or its link rather than evidence about the post - \
                     most of the outstanding articles were never requested.",
                ),
                n => msg.push_str(&format!(
                    " {n} segment(s) WERE confirmed missing by every server that has \
                     the post, so this release is short as well as cut off; the rest \
                     were never requested and say nothing either way.",
                )),
            }
            msg.push_str(" Retrying resumes from the journal and refetches only the gaps");
            if !causes.dead_servers.is_empty() {
                // The usual reason a pool starves into a stall: a server
                // in the fleet that never worked, so its share of the
                // articles has nowhere to go.
                msg.push_str(&format!(
                    "; no usable connection was ever made to {} - a server that never \
                     connects starves the pool of the articles routed to it",
                    causes.dead_servers.join(", ")
                ));
            }
            // OUR failure. The opening was chosen for this kind (see
            // the comment above it); now it is stated rather than
            // spelled.
            return (FailKind::Transport, msg);
        }
        // No server ever said "gone" - blaming the post would be a lie.
        let all_transport = causes.missing_430 == 0
            && causes.retention_excluded == 0
            && causes.transport_failed > 0;
        // Nothing whatsoever arrived, and every loss was a server saying
        // 430 with all of them answering: the post is not damaged, it is
        // GONE. Its own opening, because the daemon must treat it
        // differently from a post that is merely short - `FailKind::Gone`
        // still reports to an indexer but does NOT arm an automatic retry,
        // which against a wholly dead post only spends the same minutes
        // again. Positive evidence only (a segment census that accounts
        // for every article asked for), never the mere ABSENCE of other
        // causes - a caller with no per-slot accounting leaves the totals
        // at 0 and must fall through to the classic opening.
        // The byte belt tolerates arrivals when the post carries
        // recovery slots: `bytes_arrived` is wire bytes over ALL slots,
        // so a takedown that left the `.par2` volumes up (a common
        // shape) used to block this verdict on the parity's bytes alone
        // and spend a pointless full retry proving the same payload
        // absent. The payload side needs no byte belt - the census term
        // above it already says every payload segment resolved to
        // nothing (error-detection audit 20 Aug, A2).
        let post_gone = causes.total_segments > 0
            && causes.missing_segments >= causes.total_segments
            && (causes.bytes_arrived == 0 || causes.par2_slots > 0)
            && causes.missing_430 > 0
            && causes.transport_failed == 0
            && causes.retention_excluded == 0
            && causes.dead_servers.is_empty()
            // A server that served and then LEFT disqualifies the verdict
            // for exactly the reason a server that never connected does:
            // from the moment its last worker retired it stopped voting,
            // and "not one article is on ANY server" is a claim about a
            // quorum that was still whole. It is the more dangerous of the
            // two, because `ever_connected` stays true and nothing else in
            // this struct would have noticed (audit 20 Aug, A3).
            && causes.left_servers.is_empty()
            && causes.post_age_days >= GONE_MIN_AGE_DAYS;
        // Every article accounted for, nothing lost anywhere, and files
        // short all the same: that is the yEnc coverage census speaking,
        // not missing segments. It must NOT open with "download
        // incomplete", which `fail_kind` maps to `MissingArticles` and
        // so arms an automatic retry - and the retry resumes from the
        // journal, replays exactly the same spans, and arrives at
        // exactly the same gap. A deterministic loop, whose message
        // meanwhile blamed the post for lost segments the census itself
        // says never happened ("1 file(s) with missing segments; 0 of
        // 240 segment(s) never arrived" in one breath). Falls through to
        // `FailKind::Local`, which does not retry.
        // `derrs == 0` belongs here as much as the rest of it. A decode
        // or write error decrements `remaining` and increments only the
        // error counters, so `missing_segments` stays at zero while the
        // failed article's bytes ARE a real gap - and the census flags
        // the slot. Without this term the opening claimed "every article
        // arrived and decoded" in the same breath as "1 decode/write
        // errors", and worse, it moved the job from
        // `FailKind::MissingArticles` to `Local`, which does not retry.
        // A corrupt article is exactly the case a journal-resume retry
        // can heal, so the previous opening was RIGHT for it: the bytes
        // were posted, they merely arrived damaged.
        // The three cause counters count every slot alike, but the two
        // payload terms above them (`missing_segments`, `derrs`) are
        // payload-only - so one 430 on a `.vol` article used to defeat
        // this verdict and fall through to "1 file(s) with missing
        // segments; 0 of 240 segment(s) never arrived" in one breath,
        // the exact self-contradiction this branch exists to eliminate.
        //
        // The counters ARE the payload's now (sweep 8, M7), so this
        // asks the question directly instead of subtracting the
        // recovery noise back out of a flat total: no payload segment
        // was lost to any cause. Same conservative direction - an
        // outcome whose id maps to no slot counts as payload, so it
        // still blocks the verdict.
        let size_header_lies = causes.total_segments > 0
            && causes.missing_segments == 0
            && derrs == 0
            && causes.missing_430 + causes.transport_failed + causes.retention_excluded == 0;
        // Which of the two failed - the payload, or the recovery set that
        // was supposed to fix it. See [`recovery_is_the_casualty`] for
        // why it sits exactly here in the precedence.
        let recovery_casualty =
            recovery_is_the_casualty(causes, derrs, post_gone, size_header_lies, all_transport);
        // The seam's wording: a verdict about the SOURCE, with no
        // segment census behind it to quote. "this repair needed" is
        // SCOPE, for the overlap arm: unqualified, it lands after a
        // census saying 4% and reads as walking that census back. Exact
        // rather than decorative - `Unservable` measures the volumes
        // `fetch_volumes` asked for, a subset of the set chosen for the
        // damage in hand.
        //
        // ONE ladder for the kind and the words, so an arm cannot be
        // added to either half alone. Each kind here is the one
        // `fail_kind` reads back off the opening this arm writes, and
        // the arms' own comments carry the reasons.
        let (kind, mut msg) = if size_header_lies {
            // `Local` in the string classifier too, and deliberately:
            // re-downloading cannot post bytes the poster never posted,
            // so this must not be transient.
            (
                FailKind::Local,
                format!(
                    "post size header disagrees with its parts: every payload article \
                 arrived and decoded, but {incomplete} file(s) declare more bytes than \
                 the post actually carries, {derrs} decode/write errors. Re-downloading \
                 cannot change this - the missing bytes were never posted"
                ),
            )
        } else if post_gone {
            (
                FailKind::Gone,
                format!(
                    "post is gone: not one of the {} article(s) is on any server - all \
                 {incomplete} file(s) came back empty and none of the payload \
                 arrived, {derrs} decode/write errors",
                    causes.total_segments
                ),
            )
        } else if all_transport {
            (
                FailKind::Transport,
                format!(
                    "download failed on connection errors: {incomplete} file(s) lost segments \
                 to transport failures ({} in all - no server said any article was \
                 missing), {derrs} decode/write errors",
                    causes.transport_failed
                ),
            )
        } else if recovery_casualty {
            // Same OPENING WORDS as the plain arm below, and that is
            // deliberate rather than lazy. `fail_kind` classifies on
            // "download incomplete", so any other opening moves this
            // shape out of `MissingArticles` - and `MissingArticles` is
            // the only kind the age gate applies to, so the 644-day post
            // that raised this would get its automatic retry back and
            // spend a second 13 GB download proving the same recovery
            // set unobtainable. That is a policy change, and item 17 is
            // not one: what was wrong here was never the class, it was
            // that the first thing the user read was a count of holes in
            // a payload that was 99.2% whole. The cause goes in front of
            // the counts; the counts follow, unchanged, in the census
            // clause below.
            // TWO sources of evidence, NOT alternatives: the census is
            // the eager path (a recovery file that got a slot, dying
            // like any other article), the seam is §282 item 4's
            // verdict out of the repair ladder, where a DEFERRED
            // volume's fetch happens. Both can fail in one job and each
            // is a different remedy, so each speaks when it has
            // something to say. Selecting on `recovery_segments > 0`
            // was wrong on the very shape the seam exists for: a
            // conventionally named set gets no `Par2Volume` slot, so
            // that counter is 1 for the index that ARRIVED while
            // `recovery_unusable()` is 0, and the sentence read "0 of
            // the post's 1 ... are missing or damaged, so ... have no
            // parity left to rebuild them from". `recovery_casualty`
            // guarantees at least one arm - `mostly_gone` cannot hold
            // with `recovery_unusable()` at zero. Full story in TODO
            // §282 item 17; found by §283 item 13's assertion.
            let census = (causes.recovery_unusable() > 0).then(|| {
                format!(
                    "{} of the post's {} PAR2 recovery segment(s) are missing or damaged",
                    causes.recovery_unusable(),
                    causes.recovery_segments
                )
            });
            let lost = match (census, causes.recovery_unobtainable) {
                (Some(c), true) => format!("{c}, and {UNOBTAINABLE}"),
                (Some(c), false) => c,
                (None, _) => UNOBTAINABLE.to_string(),
            };
            // The same kind as the plain arm below, for exactly the
            // reason its opening words are the same - see the block
            // comment above this arm.
            (
                FailKind::MissingArticles,
                format!(
                    "download incomplete: the recovery data is what failed, not the payload - \
                 {lost}, so the {incomplete} file(s) that came up short have no parity \
                 left to rebuild them from, {derrs} decode/write errors"
                ),
            )
        } else {
            (
                FailKind::MissingArticles,
                format!(
                    "download incomplete: {incomplete} file(s) with missing segments, \
                 {derrs} decode/write errors"
                ),
            )
        };
        append_evidence_clauses(
            &mut msg,
            causes,
            derrs,
            &VerdictFlags {
                post_gone,
                size_header_lies,
                all_transport,
                recovery_casualty,
            },
        );
        (kind, msg)
    } else {
        // DECODE and WRITE errors share one counter but have opposite
        // remedies, and the sample says which happened: a decode error
        // means the SERVER handed us bytes that failed their own yEnc
        // CRC or length check, where free space and permissions are
        // irrelevant and a re-fetch (often from another provider) is the
        // fix. Sending someone to check their disk over a corrupt
        // article is a wild goose chase - found by the wire-corruption
        // leg of the 11 Aug soak, which serves deliberately damaged
        // articles from a healthy machine.
        // Which of the two it was is the PRODUCER's verdict, carried
        // here as a value: both writers in `get/workers.rs` know it at
        // the moment they record the sample, and until 26 Aug 2026 they
        // spent it on the opening words of a string this line then read
        // back. See [`DecodeFault`].
        let corrupt = causes
            .decode_sample
            .as_ref()
            .is_some_and(|s| s.fault == DecodeFault::Corrupt);
        let mut msg = if corrupt {
            format!(
                "the articles did not decode: {derrs} damaged article(s) and no missing \
                 segments - every article arrived, but their contents failed the yEnc \
                 checks, so the copies on the server are corrupt. Retrying re-fetches \
                 them, and a second provider usually carries a clean copy"
            )
        } else {
            format!(
                "could not write the download: {derrs} decode/write error(s) and no missing \
                 segments - every article arrived, so check free space, permissions and the \
                 log above"
            )
        };
        if let Some(e) = &causes.decode_sample {
            msg.push_str(&format!(" (first error: {})", e.text));
        }
        // Both spellings are about THIS machine or the copies on the
        // server, never about the post being short - which is what the
        // string classifier's catch-all already answers here. Stated so
        // the answer no longer depends on the catch-all staying put.
        (FailKind::Local, msg)
    }
}

/// The post's age in days, read back off the clause `incomplete_reason`
/// wrote - `None` when the message carries no age at all.
///
/// The census computes the age, spends it on one clause of one sentence
/// and then throws it away: the terminal failure reaches the daemon as
/// that sentence and nothing else (the same reason `fail_kind` is
/// derived from the message rather than stored on the job). The one
/// automatic retry has to know how old the post is BEFORE it spends a
/// second full download proving the same articles absent, so it reads
/// the figure back out rather than threading a number through the whole
/// pipeline for one predicate.
///
/// `None` for every message that has no such clause - a dateless NZB, a
/// post younger than a day, a transport failure, a repair verdict - and
/// `None` is the retry-anyway direction, which is the safe one: the cost
/// of a wrong suppression is a job that needed one more try, the cost of
/// a wrong retry is only a duplicate download.
///
/// Prose gets rewritten, so the round trip against the producer is a
/// test (`the_age_clause_reads_back`) and not a hope. Should the wording
/// ever drift out from under this, the gate stands down to today's
/// behaviour instead of misfiring.
pub fn post_age_from_message(msg: &str) -> Option<u32> {
    msg.split_once("; the post is ")?
        .1
        .split_once(" day(s) old, well past the minutes-to-hours")?
        .0
        .parse()
        .ok()
}

/// Is a missing-articles failure's loss PROVEN stale - the post old
/// enough that propagation cannot be the answer, with nothing left in
/// the census that a retry could heal?
///
/// The automatic-retry gate used to ask only the age, and the age clause
/// stands down only for `all_transport`, which one confirmed 430 makes
/// false. So a run that lost most of its segments to timeouts, resets or
/// a server that never connected AND happened to collect one genuine
/// takedown was called an aged dead post: the single automatic retry was
/// suppressed, and a suppressed retry also makes the failure FINAL - the
/// release is reported to the indexer as dead, the FailureLink re-grab
/// runs and a held duplicate is promoted. By this module's own words a
/// transport loss is "a fault on THIS machine or its link", and a
/// journal-resume retry is exactly what heals it (Codex sweep 3, M8).
///
/// Read back off the message because that is all a job record carries.
/// Both clauses are emitted a few hundred lines above and the round trip
/// is pinned by `an_ambiguous_loss_is_never_proven_stale`.
pub fn missing_articles_proven_stale(msg: &str) -> bool {
    post_age_from_message(msg).is_some_and(|days| days >= GONE_MIN_AGE_DAYS)
        && !msg.contains("lost to transport/connection errors, not takedowns")
        && !msg.contains("no usable connection")
        // Third exclusion, same shape and the same reason: age settles
        // whether PROPAGATION can still help, and nothing else. Damaged
        // articles are bytes that were posted, so a journal-resume retry
        // can still heal them however old the post is.
        && !msg.contains("damaged articles rather than absent ones")
        // Fourth exclusion, and the purest ambiguous loss of the lot:
        // retention-excluded segments were never REQUESTED - the
        // configured retention_days pre-seeded the refusal mask, so no
        // server ever gave an opinion. An old post behind a mis-set
        // retention_days therefore looked exactly like a proven-dead
        // one, lost its retry, and the suppression made the failure
        // final: indexer dead-report, FailureLink re-grab, duplicate
        // promotion - all from the user's own settings row. Fixing the
        // setting and retrying is precisely what heals it.
        && !msg.contains("older than every server's configured retention")
        // Fifth exclusion, the mid-run twin of the second one above. A
        // server that authenticated, served, and then left (permanent
        // refusal, spent block or quota, outage budget blown,
        // connect-attempt cap) shrinks the quorum silently: from that
        // moment `live_mask` stops counting it, so the survivors' 430s on
        // the segments it alone carried resolve "unanimous" without it.
        // That is an ambiguous loss by the same definition as a server
        // that never connected, and it must not lose the run its one
        // automatic retry - a suppressed retry is also FINAL (indexer
        // dead-report, FailureLink re-grab, duplicate promotion). The
        // clause text IS the contract; the round trip is pinned by
        // `a_server_that_left_mid_run_is_never_proven_stale` (audit 20
        // Aug, A3).
        && !msg.contains("served for part of the run and then stopped")
        // Sixth exclusion, and the same physical event as the fifth
        // reached through the other latch. `MissingCause::Unasked` is
        // the pool SAYING that a departure decided these segments,
        // where the fifth exclusion infers it from a server having
        // left; the two normally fire together, and this one covers the
        // run that reached a terminal unasked verdict while already
        // aborting or draining, where `note_server_dark` skips the
        // `left_mid_run` latch and nothing else here would notice. Same
        // direction as all five above - preserve the one automatic
        // retry, because a suppressed retry is also FINAL (indexer
        // dead-report, FailureLink re-grab, duplicate promotion) - and
        // preserving it is exactly right for a loss no complete fleet
        // ever voted on. The clause text IS the contract; the round
        // trip is pinned by `an_unasked_loss_is_never_proven_stale`.
        && !msg.contains("written off while the fleet was short")
}

/// A zip an extraction pass reported and could not produce, with the
/// severity a caller needs to decide what to do about it.
pub struct UnsupportedArchive {
    /// What to show the user: the archive name, prefixed with its
    /// subdirectory when it isn't at the top of the output dir.
    pub display: String,
    /// `zip` / `spanned zip` / `split zip`.
    pub shape: &'static str,
    /// Nothing else landed, so this archive IS the payload - the user
    /// got nothing they can use. False for a sidecar (a `Subs/subs.zip`
    /// beside a feature that unpacked fine): still worth a log line,
    /// not worth alarming anyone over.
    pub blocking: bool,
}

impl UnsupportedArchive {
    /// The sentence the user reads, in the log and (when blocking) on
    /// the job in history.
    pub(crate) fn message(&self) -> String {
        if self.blocking {
            format!(
                "⚠ {} ({}) could not be unpacked - it is damaged, encrypted, or uses a \
                 compression method this build does not carry, so the payload is still \
                 packed. The verified archive is in the output directory; unpack it \
                 with your own tool.",
                self.display, self.shape
            )
        } else {
            format!(
                "note: {} ({}) left packed beside the payload - it could not be \
                 unpacked. The rest of the download is complete.",
                self.display, self.shape
            )
        }
    }
}

impl UnsupportedArchive {
    /// The same sentence as a tagged log line: a warning when the
    /// payload itself is still packed, a note otherwise. The history
    /// text keeps its own glyph; the level carries it here.
    pub fn log(&self) {
        let msg = self.message();
        if self.blocking {
            tracing::warn!(target: "extract", "{}", msg.trim_start_matches("⚠ "));
        } else {
            tracing::info!(target: "extract", "{msg}");
        }
    }
}

/// The first zip anywhere under the output dir, if any.
///
/// This is what downgrades "zip present" from a job failure to a
/// reported gap, so it has to see everything the detection side sees -
/// which since zip joined [`is_extractable_archive`] means the whole
/// tree, not just the top level: a pass now descends into a subfolder
/// zip and reports it, and a `false` this function could not explain
/// would fail the job with the wrong reason.
///
/// Traversal skips our own scratch dirs, exactly like `snapshot_recursive`.
pub fn unsupported_archive_present(root: &std::path::Path) -> Option<UnsupportedArchive> {
    // Usenet furniture is not payload: a directory holding nothing but a
    // zip and its par2 set still means the user got nothing usable.
    const FURNITURE: &[&str] = &[
        "par2", "sfv", "nfo", "nzb", "url", "txt", "srr", "srs", "diz", "md5", "sha", "sha256",
        "website",
    ];
    let mut dirs = vec![root.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        let Ok(rd) = std::fs::read_dir(&dirs[i]) else {
            i += 1;
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir())
                && !e.file_name().to_string_lossy().starts_with(".nzbfast")
            {
                dirs.push(e.path());
            }
        }
        i += 1;
    }
    dirs.sort();

    let mut first: Option<(nzbkit::zip::Finding, PathBuf)> = None;
    let mut parts: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for d in &dirs {
        for f in nzbkit::zip::scan(d) {
            // Still a zip part either way: whether or not we unpacked it,
            // the container is not the user's payload, so the test below
            // must not count it as one.
            parts.extend(f.parts.iter().cloned());
            // ...but a container whose contents ALREADY sit beside it is
            // not a gap. The spent-intermediate sweep keeps a container
            // whenever two independent sets share a directory (it cannot
            // prove either is consumed), so a job that unlocked two
            // encrypted zips from the passwords file and delivered both
            // payloads still ends with the containers on disk - and this
            // function reported one of them as "left packed ... it could
            // not be unpacked", which is the opposite of what happened.
            if zip_already_delivered(d, &f) {
                continue;
            }
            if first.is_none() {
                first = Some((f, d.clone()));
            }
        }
    }
    let (found, dir) = first?;

    // Payload = anything that isn't one of the zip parts and isn't
    // furniture. If none exists, the zip is all the user got.
    let mut payload = false;
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else {
            continue;
        };
        for e in rd.flatten() {
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let p = e.path();
            if parts.contains(&p) {
                continue;
            }
            // Our own bookkeeping (`.nzbfast.journal`) and the OS's
            // droppings are not the user's payload - counting the journal
            // as one made every still-packed post look like it had
            // landed something usable beside the archive.
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let ext = p
                .extension()
                .map(|x| x.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !FURNITURE.contains(&ext.as_str()) {
                payload = true;
            }
        }
    }

    let display = match dir.strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => {
            format!("{}/{}", rel.display(), found.name)
        }
        _ => found.name.clone(),
    };
    Some(UnsupportedArchive {
        display,
        shape: found.shape.label(),
        blocking: !payload,
    })
}

/// Has this container's content already been written beside it?
///
/// True only when EVERY file entry exists at its own path under `dir`
/// with the declared uncompressed size. That is deliberately strict: a
/// partial match means some of the archive is still unexploded, which is
/// exactly the gap this module exists to report, and a size match is what
/// separates "we extracted it" from "an entry happens to share a name
/// with something in the download".
///
/// A container we cannot open answers false - unreadable is a gap, not a
/// delivery. So does one naming a path outside `dir` (`../`, absolute,
/// or a Windows drive letter): the extractor refuses those, so nothing
/// under `dir` can be its output, and resolving them here would let a
/// crafted entry name point the check at an unrelated file.
pub fn zip_already_delivered(dir: &std::path::Path, f: &nzbkit::zip::Finding) -> bool {
    let Ok(archive) = nzbkit::zip::Archive::open(&f.parts) else {
        return false;
    };
    let files: Vec<_> = archive.entries().iter().filter(|e| !e.is_dir).collect();
    if files.is_empty() {
        return false;
    }
    files.iter().all(|e| {
        let name = e.name.replace('\\', "/");
        let safe = !name.starts_with('/')
            && !name.contains(':')
            && name.split('/').all(|c| c != ".." && c != ".");
        safe && std::fs::metadata(dir.join(&name)).is_ok_and(|m| m.is_file() && m.len() == e.size())
    })
}

/// `Release.Name{{password}}.nzb` (also `{pw}` / `password=pw`) → the
/// embedded password (the conventions SABnzbd/NZBGet users and several
/// indexers rely on). Shared parser: `crate::relname::name_password`.
pub fn braces_password(nzb_path: &std::path::Path) -> Option<String> {
    let name = nzb_path.file_name()?.to_string_lossy();
    let name = name.trim_end_matches(".nzb");
    crate::relname::name_password(name).map(|(pw, _)| pw)
}

/// Is this demote one the 7z disk post-pass already owns? A top-level `.7z`
/// chase that gives up materializes its archive into the output directory,
/// which is exactly that pass's input.
///
/// It is filtered out of the unrar ladder entirely rather than added to
/// [`fallback_needs_disk_unpack`]'s exclusions, because its reason text
/// steers all three arms of that ladder and every one of them is wrong for a
/// 7z: the retention-cap wording reads as an unowned RAR set, the
/// encrypted-7z wording reads as a locked one, and both end at `try_unrar`
/// over a directory with no RAR in it - which answers false and fails a job
/// whose payload unpacks perfectly one pass later.
pub fn sevenz_disk_fallback(why: &str) -> bool {
    why.starts_with(nzbkit::extract::SEVENZ_DISK_FALLBACK_PREFIX)
        // A demoted top-level ZIP chase is the same story with a
        // different ladder step: the materialized `.zip` is the disk
        // post-pass's own input (its step 5), and its reason text -
        // "encrypted", "held-bytes cap" - would steer the RAR arms just
        // as wrongly.
        || why.starts_with(nzbkit::extract::ZIP_DISK_FALLBACK_PREFIX)
        // And the third: a volume the offset-0 sniff started inside a
        // self-extractor's stub (TODO 94 C) materializes as the posted
        // `.exe`, which the tail's SFX arm owns. Found on a COMPRESSED SFX
        // RAR, which took this route every time until the chase learned
        // the offset (724f65e0f) and still does whenever a group demotes
        // for any other reason: unmarked, its "compressed" reason ran the
        // ladder's first arm - `unrar` over a directory holding one
        // `.exe`, which cannot succeed - and failed a job whose payload
        // the SFX arm unpacks one pass later. Measured against the real
        // libarchive stub 23 Aug 2026: the same file posted with the stub
        // past the first article, so the sniff never fired and the `.exe`
        // landed as plain data, unpacked.
        || why.starts_with(nzbkit::extract::SFX_DISK_FALLBACK_PREFIX)
        // And a fourth: a demoted top-level TAR chase (TODO 163 item
        // 6). Since the disk half landed (23 Aug 2026) this is the same
        // story as the two above rather than a special case: the
        // materialized `.tar` is the post-pass ladder's own input (its
        // step 6), and its reason text ("symlink", "held-bytes cap")
        // would steer the RAR arms at a directory holding no RAR. It
        // was filtered here before that arm existed too, on the second
        // half of that sentence alone.
        || why.starts_with(nzbkit::extract::TAR_DISK_FALLBACK_PREFIX)
}

/// An SFX demote the tail's SFX arm should NOT be handed: locked, with no
/// password to try. The carve has nothing to do then - `extract_sfx` hands
/// the archive to a reader that refuses it - and the job would fail over a
/// `.exe` that is perfectly fine on disk, where the same set inside a plain
/// `.rar` finishes Completed with the 🔒 prompt and unpacks on a retry.
///
/// "compressed" is tested FIRST, exactly as the tail's arms order
/// themselves, because [`nzbkit::rar::MapBlocker::NotStore`] reads
/// "compressed or encrypted entries" and carries BOTH words. A bare
/// "encrypted" test therefore claims every compressed self-extractor and
/// prints a password prompt for an archive that needs none - which is what
/// it did, on the first run after it was written.
pub fn sfx_locked_fallback(why: &str) -> bool {
    why.starts_with(nzbkit::extract::SFX_DISK_FALLBACK_PREFIX)
        && !why.contains("compressed")
        && (why.contains("encrypted") || why.contains("password"))
}

/// Does a level-0 extraction fallback leave its volumes UNOWNED, i.e. is the
/// on-disk unrar pass the only thing left that would unpack them?
///
/// Answered by exclusion rather than by listing the demote reasons, because
/// that list was wrong twice. Memory pressure ("held-bytes cap", "incomplete
/// mapping") once let a 2 GB NAS finish a 190 GB job with 431 loose volumes
/// and exit 0; then the integrity gate's own demotes (a BLAKE2sp-only entry,
/// a stored CRC that did not match, headers that do not describe a complete
/// file) shipped a directory of loose .rar volumes with no payload at all,
/// reported Completed. A demote says "let the disk path check it", and only
/// the unrar pass actually does that: it verifies CRC32 *and* BLAKE2sp, so a
/// set that is fine unpacks and the job still succeeds (cost: double I/O),
/// while an incomplete or header-broken one fails the job honestly. Any
/// reason added later therefore lands here by default.
///
/// The exclusions are the reasons somebody else already owns:
///   - "nested fallback:" (see `extract::nested_reason`) - the inner layer is
///     already materialized and belongs to the post-extraction pass, which
///     runs the inner PAR2 repair BEFORE unpacking; unrarring it here would
///     fail on damage that repair is about to fix.
///   - encrypted / password / compressed - the caller's own branches.
///   - "not a RAR volume", "never classified", "unclassified-holds budget" -
///     the slot never was an archive, so there is no set for unrar to open
///     and it would fail a job that is fine today.
///   - "materialized for repair" - the PAR2 path demoted the group itself so
///     par2 could see the volumes on disk, and it re-extracts them (and then
///     REMOVES them) as soon as the repair lands. Running the disk pass over
///     what it leaves behind finds no volumes at all.
///
/// A demote the 7z post-pass owns never reaches here at all - see
/// [`sevenz_disk_fallback`], which filters it out of the whole ladder.
pub fn fallback_needs_disk_unpack(why: &str) -> bool {
    !why.starts_with("nested fallback:")
        && !why.contains("encrypted")
        && !why.contains("password")
        && !why.contains("compressed")
        && !why.contains("not a RAR volume")
        && !why.contains("never classified")
        && !why.contains("unclassified-holds budget")
        && !why.contains("materialized for repair")
}

/// The in-stream extraction demoted because the bomb guard refused it -
/// so the disk ladder below must not run at all, and the job fails here
/// with the verdict that was actually reached.
///
/// Every rung under a demote assumes the demote was about the ARCHIVE
/// (compressed, encrypted, a CRC that did not hold) and that a second
/// engine may therefore do better. A bomb verdict is about the DISK, and
/// no engine does better on a disk: the native disk pass re-refuses (its
/// own `BombGuardWriter`, same budget) and the external `unrar` has no
/// budget at all and simply fills the volume. Observed 22 Aug 2026 - a
/// 2 GB-of-zeros RAR5 refused twice, extracted until ENOSPC on the
/// third rung, and reported as "the verified volumes could not be
/// unpacked after a fallback".
///
/// Deliberately NOT worded to match `serve::job::disk_full_failure`:
/// that classifier arms the min-free hold, which puts the job back on
/// the queue to wait for space. This is not a job that ran out of room
/// in passing - it is one whose archive cannot fit, and a hold would
/// re-run it forever.
///
/// Returns the job-failure message, having said the same thing once on
/// the console. `None` when no fallback carries the verdict, which is
/// every ordinary demote.
pub fn bomb_fallback<'a>(reasons: impl IntoIterator<Item = &'a str>) -> Option<String> {
    if !reasons.into_iter().any(nzbkit::disk::bomb_verdict) {
        return None;
    }
    println!(
        "⚠ unpacking this archive needs more space than the disk has \
         (possible decompression bomb) - the verified volumes were kept"
    );
    Some(bomb_failure())
}

/// The job-failure sentence a bomb verdict composes, wherever the
/// verdict is reached.
///
/// One function because the sentence has two loose requirements it must
/// keep at every site, and neither is visible from a literal: it has to
/// CARRY [`nzbkit::disk::BOMB_VERDICT`] (so `bomb_verdict` still reads
/// as true off a job failure quoted back into the ladder), and it must
/// NOT read as a disk-full to [`crate::failkind::disk_full_failure`]
/// (which arms the min-free hold and would requeue the job to wait for
/// space it can never have enough of). `bomb_fallback` above is the
/// demote-side site; [`crate::rarfix::try_unrar_spent_why`] is the two
/// refusals INSIDE the ladder, which have no demote reason to carry
/// anything for them.
pub fn bomb_failure() -> String {
    format!(
        "{} - the verified volumes were kept",
        nzbkit::disk::BOMB_VERDICT
    )
}

/// Does a successful unlock ANSWER this job-failure sentence?
///
/// The clearing predicate the manual-unlock tail spends once the archive
/// has actually come open: the Reason the row still carries has just
/// been made untrue, so it must go, and anything else must stay - a
/// failure the download itself recorded outranks whatever the unlock
/// has to say.
///
/// Three sentences, and the third is the one a literal list cannot see.
/// The refused arm of that same tail writes [`unpack_failure`], which
/// carries the ladder's OWN reason when it named one - today a
/// [`bomb_failure`], which is about the DISK and not the password. A
/// user who frees space and unlocks correctly afterwards was left with
/// a Completed row whose Reason read "extraction exceeded available
/// disk space" forever. Matched with [`nzbkit::disk::bomb_verdict`],
/// the matcher `bomb_failure` is documented to keep true, rather than
/// with a fourth literal that would drift the first time the sentence
/// is reworded.
pub fn unlock_answers(fail_message: &str) -> bool {
    fail_message == "password required to unpack"
        || fail_message == "password did not unlock the archive"
        || nzbkit::disk::bomb_verdict(fail_message)
}

/// The job failure a refused disk unpack composes: the ladder's OWN
/// reason when it named one, else the caller's generic wording.
///
/// Four sites word that generic sentence, and every one of them blames
/// the ARCHIVE - "the verified volumes could not be unpacked
/// (compressed set, or the password is wrong)", "…after a fallback",
/// "resumed job: the verified volumes on disk could not be extracted",
/// "PAR2 repair succeeded but re-extraction failed". Each is right for
/// the failure it was written for and wrong for the only refusal that
/// names itself: a bomb verdict, which is about the DISK. The console
/// line said so all along; this is what carries it to the user and to
/// any *arr reading the job's failure text.
///
/// One function rather than four `unwrap_or_else` closures because the
/// rule - a named reason WINS - is the whole fix, and a site that
/// quietly stopped preferring it would look exactly like the three that
/// still did.
pub fn unpack_failure(why: Option<String>, generic: &str) -> String {
    why.unwrap_or_else(|| generic.to_string())
}

/// Unpack compressed RAR volumes with a bundled/system unrar. Volumes are
/// already PAR2-verified; without a password `-p-` refuses prompts
/// (encrypted sets are left alone), `-o+` overwrites partials from
/// aborted attempts. The daemon also calls this with a job's password
/// (mode=set_password) to unlock encrypted sets after the fact.
/// First volume of the RAR set: the lowest-numbered `.partNNN.rar` at any
/// digit width (part1 / part01 / part001 - literal ".part01."/".part1."
/// matching missed 3-digit sets and let a stray sample.rar/subs.rar shadow
/// the real first volume), else the lexically first plain `.rar`.
pub fn first_rar_volume(rars: &[PathBuf]) -> Option<PathBuf> {
    rars.iter()
        .min_by_key(|p| {
            let n = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();
            let part = n.rfind(".part").and_then(|i| {
                let d: String = n[i + 5..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                d.parse::<u64>().ok()
            });
            (part.is_none(), part.unwrap_or(0), n)
        })
        .cloned()
}

#[cfg(test)]
#[path = "diag/main_tests.rs"]
mod main_tests;
