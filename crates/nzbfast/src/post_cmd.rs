//! `nzbfast post` - upload files as yEnc articles to a test group and
//! emit the matching NZB (ops tool; runbook: bench/nested-corpus/POSTING.md).
//!
//! Server selection is explicit and mandatory: `--post-server` must name
//! exactly one configured server (host, or host:port when two entries
//! share a host). There is deliberately NO default - posting never picks
//! "the first server" on its own.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

use anyhow::{Context, Result};
use nzbkit::config::{Config, ServerConfig};
use nzbkit::post::{self, PostOpts};

pub struct PostArgs {
    pub paths: Vec<PathBuf>,
    pub post_server: String,
    pub nzb: PathBuf,
    pub group: String,
    pub from: String,
    pub msgid_domain: String,
    pub article_size: usize,
    pub title: Option<String>,
    pub connections: usize,
    pub verify: bool,
    pub allow_empty: bool,
    /// No-RAR mode: random subject and yEnc `name=` per file, so a
    /// scraper without the NZB cannot tie an article to a release.
    pub obfuscate: bool,
    /// With `obfuscate`, leave the yEnc `name=` empty rather than
    /// carrying the same random token the subject does.
    pub obfuscate_empty_name: bool,
    /// Build and post a PAR2 set beside the payload, carrying the REAL
    /// names and directory tree in its FileDesc packets. `Some(0)` is a
    /// verify-only set (no recovery slices); higher is a percentage of
    /// the input slice count.
    pub par2: Option<u32>,
    /// PAR2 slice size in bytes; `None` derives one from the payload.
    pub par2_block_size: Option<u64>,
    /// Base name of the emitted `.par2` files; `None` mints a random
    /// one under `obfuscate` and uses the NZB's stem otherwise.
    pub par2_base: Option<String>,
}

/// Resolve `--post-server` against the config: exact host match
/// (case-insensitive), or `host:port` when one host has several entries.
/// Anything but exactly one enabled match is a hard error.
fn select_server(cfg: &Config, wanted: &str) -> Result<ServerConfig> {
    let want = wanted.trim().to_ascii_lowercase();
    let matches: Vec<&ServerConfig> = cfg
        .servers
        .iter()
        .filter(|s| {
            s.host.to_ascii_lowercase() == want
                || format!("{}:{}", s.host.to_ascii_lowercase(), s.port) == want
        })
        .collect();
    let hosts = || {
        cfg.servers
            .iter()
            .map(|s| {
                format!(
                    "  {}:{}{}",
                    s.host,
                    s.port,
                    if s.enabled { "" } else { " (disabled)" }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    match matches.as_slice() {
        [] => anyhow::bail!(
            "--post-server {wanted:?} matches no configured server. Configured servers:\n{}",
            hosts()
        ),
        [one] => {
            anyhow::ensure!(
                one.enabled,
                "--post-server {wanted:?} is disabled in the config - enable it explicitly before posting"
            );
            Ok((*one).clone())
        }
        many => anyhow::bail!(
            "--post-server {wanted:?} matches {} server entries - disambiguate with host:port. Configured servers:\n{}",
            many.len(),
            hosts()
        ),
    }
}

/// Persist a retrieval index, never on top of someone else's file.
/// Normally the claim taken before the upload is still ours - the EMPTY file
/// this run created - and the index goes straight into it. If it has been
/// moved or removed underneath us, or something with bytes in it now sits
/// there, the index lands under a name only this process holds: whatever is
/// at the claim path is another run's only record of its own articles, and
/// truncating it would strand them. A write that fails at the claim falls
/// back to that unique name too, so one bad write cannot lose the index.
fn write_rescue(claim: &std::path::Path, xml: &str) -> std::io::Result<PathBuf> {
    // Write THROUGH the claim only while it is still empty, and check the
    // length on the open handle rather than the path, so the file we measure
    // is the file we write.
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(claim)
        && f.metadata().is_ok_and(|m| m.len() == 0)
    {
        use std::io::Write;
        match f.write_all(xml.as_bytes()) {
            Ok(()) => return Ok(claim.to_path_buf()),
            // A half-written claim reads exactly like an earlier run's
            // rescue index, and the next run would tell the operator to
            // publish it. Put it back to the empty claim it was, then
            // try a name of our own.
            Err(_) => {
                let _ = f.set_len(0);
            }
        }
    }
    let alt = |suffix: String| -> PathBuf {
        let mut p = claim.to_path_buf().into_os_string();
        p.push(suffix);
        PathBuf::from(p)
    };
    let pid = std::process::id();
    let mut last = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free rescue name");
    for n in 0..16 {
        let path = alt(if n == 0 {
            format!(".{pid}")
        } else {
            format!(".{pid}.{n}")
        });
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(xml.as_bytes())?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// A directory this run created and owns for the length of the run: the
/// generated `.par2` files live there between being built and being
/// posted. It is removed on EVERY exit path, including the aborts,
/// because the set is deterministic - identical members under identical
/// names produce identical bytes - so keeping it would preserve nothing
/// a rerun could not rebuild.
struct ScratchDir(PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Give back the exclusive claim this run took, so a rerun is not blocked by
/// a file that holds nothing. Best effort, and ONLY while the claim is still
/// the empty file we created: bytes at that path are a retrieval index (ours,
/// or another run's after an exotic interleaving) and are never removed.
fn release_empty_claim(claim: &std::path::Path) {
    if std::fs::metadata(claim).is_ok_and(|m| m.len() == 0) {
        let _ = std::fs::remove_file(claim);
    }
}

pub async fn run(config: &Path, args: PostArgs) -> Result<()> {
    anyhow::ensure!(
        !args.post_server.trim().is_empty(),
        "--post-server is required: name the ONE configured server to post through"
    );
    let cfg = Config::load(config)?;
    let server = select_server(&cfg, &args.post_server)?;

    let obfuscate = args.obfuscate.then_some(post::Obfuscation {
        yenc_name: if args.obfuscate_empty_name {
            post::YencName::Empty
        } else {
            post::YencName::Random
        },
    });
    anyhow::ensure!(
        args.obfuscate || !args.obfuscate_empty_name,
        "--obfuscate-empty-name only means anything with --obfuscate"
    );
    // An obfuscated post puts NO real name anywhere on the wire, so
    // something has to carry them out of band or they are simply gone -
    // and the post would look perfectly healthy while landing a
    // directory of random tokens. The PAR2 FileDesc packets are the one
    // carrier this tool can emit and other clients already read, so a
    // post that has neither is refused rather than published. `--par2 0`
    // is the cheapest way to satisfy it: names and block checksums, no
    // parity bytes at all.
    anyhow::ensure!(
        !args.obfuscate || args.par2.is_some(),
        "--obfuscate leaves no real name on the wire, so the names need a carrier: \
         add --par2 <percent> (or --par2 0 for a verify-only set that names every \
         file and builds no parity)"
    );
    let mut plan = post::plan_with(
        &args.paths,
        args.article_size,
        &post::PlanOpts {
            allow_empty: args.allow_empty,
            obfuscate,
        },
    )
    .map_err(|e| anyhow::anyhow!("planning post: {e}"))?;

    // Validate the NZB destination BEFORE posting. Every article is uploaded
    // with a fresh RANDOM Message-ID whose only retrieval index is this NZB,
    // so a write that fails AFTER the upload orphans the whole post. Reject a
    // directory or a missing parent now, then CLAIM a temp file in the
    // destination directory (exclusive create - see below) and post into that
    // temp - the real destination is only (atomically) replaced once every
    // upload succeeds, so an existing NZB is never truncated on a failed run.
    if args.nzb.is_dir() {
        anyhow::bail!("--nzb {} is a directory, not a file", args.nzb.display());
    }
    let nzb_dir = match args.nzb.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !nzb_dir.is_dir() {
        anyhow::bail!(
            "--nzb parent directory {} does not exist",
            nzb_dir.display()
        );
    }
    let nzb_tmp = {
        let mut t = args.nzb.clone().into_os_string();
        t.push(".nzbtmp");
        PathBuf::from(t)
    };
    // Exclusive claim: prove the destination is writable before a single byte
    // is uploaded, AND make the temp this run's alone. The claim has to be
    // create_new (O_EXCL) rather than a probe-then-create, for two reasons.
    //
    // A NON-EMPTY temp already sitting there is the rescue index of an earlier
    // run - one that uploaded fine but failed to publish, or one that aborted
    // partway with articles already accepted. Either way those articles are on
    // the server under randomly generated Message-IDs, and that file is the
    // only record of them; a truncating create would strand them permanently.
    //
    // And the temp path is derived purely from --nzb, so two concurrent posts
    // to the same destination share it. Without the exclusive claim both would
    // upload their own articles and both would rename onto the destination,
    // the loser's Message-IDs losing their only index. The claim makes the
    // second run stop here, before it posts anything.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&nzb_tmp)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::metadata(&nzb_tmp).is_ok_and(|m| m.len() > 0) {
                anyhow::bail!(
                    "{} already holds the retrieval index of a previous upload that \
                     did not publish - rename it to {} (or move it aside) before \
                     posting again",
                    nzb_tmp.display(),
                    args.nzb.display()
                );
            }
            anyhow::bail!(
                "{} is already claimed - another `nzbfast post` is probably writing \
                 {} right now (post elsewhere with --nzb), or the claim is stale and \
                 can be deleted",
                nzb_tmp.display(),
                args.nzb.display()
            );
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("cannot write NZB next to {}", args.nzb.display()));
        }
    }

    // The recovery set is built from the payload plan and posted BESIDE
    // it, under its own name. It has to be findable - a set nobody can
    // locate carries its names to nobody - so it is announced even when
    // the payload says nothing. The generated files live in a scratch
    // directory beside the NZB and are removed on the way out; they are
    // an artefact of the post, not something the operator asked to keep.
    let par2_scratch = args.nzb.with_extension("par2.tmp");
    // Every failure past the claim has to GIVE IT BACK, or the next run
    // meets "another post is probably writing" over an empty file this
    // one abandoned - the same reasoning `release_empty_claim` carries
    // for the post itself, applied to the step that now sits in front
    // of it. Nothing has been uploaded at this point, so the claim is
    // still the empty file we made and protects no Message-IDs.
    let built = build_par2_set(&args, &mut plan, &par2_scratch);
    let _par2_guard = match built {
        Ok(g) => g,
        Err(e) => {
            release_empty_claim(&nzb_tmp);
            return Err(e);
        }
    };

    // Counted AFTER the recovery set joined the plan, so the summary
    // line the operator reads before any byte moves is the whole post.
    let total_bytes: u64 = plan.iter().map(|f| f.size).sum();
    let total_articles: u64 = plan.iter().map(|f| f.parts as u64).sum();

    // The confirmation block: exactly which server, and what will happen.
    info!(
        target: "post",
        "server: {}:{} ({}{})",
        server.host,
        server.port,
        if server.tls { "TLS" } else { "plain" },
        if server.username.is_some() {
            ", authenticated"
        } else {
            ""
        }
    );
    info!(
        target: "post",
        "posting {} files ({:.1} MB, {} articles of ≤{} KB) to {} as {}",
        plan.len(),
        total_bytes as f64 / 1e6,
        total_articles,
        args.article_size / 1000,
        args.group,
        args.from
    );
    info!(
        target: "post",
        "message-id domain: {} · nzb: {}",
        args.msgid_domain,
        args.nzb.display()
    );

    let opts = PostOpts {
        group: args.group.clone(),
        from: args.from.clone(),
        msgid_domain: args.msgid_domain.clone(),
        article_size: args.article_size,
        title: args.title.clone(),
        connections: args.connections,
        obfuscate,
    };
    let t0 = std::time::Instant::now();
    let progress: post::Progress = Arc::new(move |done, total, sent| {
        if done == total || done % 25 == 0 {
            info!(
                target: "post",
                "{done}/{total} articles · {:.1} MB on the wire",
                sent as f64 / 1e6
            );
        }
    });
    let set = match post::post_files(&server, &plan, &opts, Some(progress)).await {
        Ok(set) => set,
        // The upload stopped partway. Whatever the server already accepted
        // is PUBLIC, under random Message-IDs that exist in exactly one
        // place: this index. Persist it before reporting the failure -
        // dropping it leaves the operator with articles on their account
        // they can neither fetch, reference, nor ask an indexer to remove.
        Err(post::PostError::Aborted { message, posted }) => {
            let n: usize = posted.files.iter().map(|f| f.segments.len()).sum();
            let rescue = post::emit_nzb(&posted);
            info!(
                target: "post",
                "ABORTED - {n} articles were accepted or duplicate-reported by the server."
            );
            match write_rescue(&nzb_tmp, &rescue) {
                Ok(at) => {
                    info!(
                        target: "post",
                        "their Message-IDs are in {} - rename it to {} to use it, \
                         or delete it once you no longer need the record.",
                        at.display(),
                        args.nzb.display()
                    );
                    anyhow::bail!(
                        "posting failed: {message} ({n} articles are posted or may be posted; \
                         their retrieval index is at {})",
                        at.display()
                    );
                }
                // Last resort: the index cannot be written, so put it where
                // the operator can still copy it out of the terminal.
                Err(e) => {
                    info!(
                        target: "post",
                        "cannot write {} ({e}) - printing the retrieval index instead:",
                        nzb_tmp.display()
                    );
                    println!("{rescue}");
                    anyhow::bail!(
                        "posting failed: {message} ({n} articles are posted or may be posted; \
                         their retrieval index could not be saved and was printed above)"
                    );
                }
            }
        }
        // Every other error means NOTHING was accepted (an upload that got
        // articles onto the server comes back as Aborted), so the claim is
        // still the empty file we made and protects no Message-IDs. Give it
        // back: keeping it would meet the next run - a rerun after a refused
        // connection, say - with "another post is probably writing", which
        // is both wrong and unhelpful.
        Err(e) => {
            release_empty_claim(&nzb_tmp);
            anyhow::bail!("posting failed: {e}")
        }
    };
    info!(
        target: "post",
        "upload complete in {:.1}s",
        t0.elapsed().as_secs_f64()
    );

    let xml = post::emit_nzb(&set);
    // Publish atomically: write the index into the pre-reserved temp, then
    // rename it over the destination. If the rename fails, the temp still
    // holds the full retrieval index for the just-completed upload.
    //
    // The write goes through the same path as the abort rescue, because the
    // stakes are identical: every article is already public under a random
    // Message-ID that exists nowhere but this index. A write that fails at
    // the claim therefore falls back to a name of our own instead of leaving
    // a torn file the next run would offer up as "the retrieval index", and
    // if no write lands at all the index is printed rather than lost.
    match write_rescue(&nzb_tmp, &xml) {
        Ok(at) => {
            std::fs::rename(&at, &args.nzb).with_context(|| {
                format!(
                    "publishing NZB to {} (index preserved at {})",
                    args.nzb.display(),
                    at.display()
                )
            })?;
            // The claim only still exists if the index took a different
            // name; it is empty, so it would block the next run for nothing.
            if at != nzb_tmp {
                release_empty_claim(&nzb_tmp);
            }
        }
        Err(e) => {
            info!(
                target: "post",
                "cannot write {} ({e}) - printing the retrieval index instead:",
                nzb_tmp.display()
            );
            println!("{xml}");
            release_empty_claim(&nzb_tmp);
            anyhow::bail!(
                "the upload succeeded but its retrieval index could not be written next to \
                 {} ({e}); nothing was published and the index was printed above",
                args.nzb.display()
            );
        }
    }
    info!(target: "post", "wrote {}", args.nzb.display());

    if args.verify {
        verify(&server, &args, &plan).await?;
    }
    Ok(())
}

/// Build the recovery set for `plan`'s payload into `par2_scratch` and
/// APPEND its files to the plan, so they post beside the payload in the
/// same run. `Ok(None)` when `--par2` was not asked for.
///
/// Its own function so the caller can give the NZB claim back on every
/// failure path in one place: this step sits between taking the claim
/// and the first byte moving, and a bare `?` here would leave an empty
/// claim behind for the next run to trip over.
fn build_par2_set(
    args: &PostArgs,
    plan: &mut Vec<nzbkit::post::PlanFile>,
    par2_scratch: &Path,
) -> Result<Option<ScratchDir>> {
    Ok(if let Some(pct) = args.par2 {
        let members: Vec<nzbkit::par2gen::Member> = plan
            .iter()
            .map(|f| nzbkit::par2gen::Member {
                name: f.rel.clone(),
                path: f.path.clone(),
            })
            .collect();
        // Exclusive, for `verify`'s reason one function down: this path
        // is derived from a user-supplied NZB name and the whole
        // directory is removed at the end, so a directory that already
        // exists is someone else's and nothing here proves otherwise.
        std::fs::create_dir(par2_scratch).map_err(|e| {
            anyhow::anyhow!(
                "PAR2 scratch directory {} already exists or cannot be created \
                 ({e}) - remove it and re-run",
                par2_scratch.display()
            )
        })?;
        let guard = ScratchDir(par2_scratch.to_path_buf());
        let base = match args.par2_base.clone() {
            Some(b) => b,
            // A base name is a subject and a filename both, so under
            // obfuscation it must say as little as the payload does.
            None if args.obfuscate => post::random_token(),
            None => args
                .nzb
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "posted".into()),
        };
        let names = nzbkit::par2gen::create_into(
            par2_scratch,
            &members,
            &base,
            &nzbkit::par2gen::Par2Spec {
                redundancy_pct: pct,
                block_size: args.par2_block_size,
            },
        )
        .map_err(|e| anyhow::anyhow!("building the PAR2 set: {e}"))?;
        info!(
            target: "post",
            "recovery set: {} file(s) at {pct}% redundancy, naming {} member(s)",
            names.len(),
            members.len()
        );
        let paths: Vec<PathBuf> = names.iter().map(|n| par2_scratch.join(n)).collect();
        // Planned separately and with NO obfuscation, so the set keeps
        // its real name on the wire.
        let par2_plan = post::plan_with(&paths, args.article_size, &post::PlanOpts::default())
            .map_err(|e| anyhow::anyhow!("planning the PAR2 set: {e}"))?;
        plan.extend(par2_plan);
        // The payload and the recovery set are planned SEPARATELY - one
        // obfuscated, one announced - so neither plan's own uniqueness
        // rule can see the other. Two files sharing a wire name produce
        // an NZB that cannot round-trip, and the reachable case is a
        // plain post whose payload happens to hold a `.par2` named like
        // the set we just built (the base defaults to the NZB's stem).
        // Cheap to check, and the alternative is a silently unusable
        // index over articles that are already public.
        let mut wire = std::collections::HashSet::new();
        for f in plan.iter() {
            anyhow::ensure!(
                wire.insert(f.posted.as_str()),
                "the recovery set and the payload would both post under the name \
                 {:?} - give the set a different --par2-base",
                f.posted
            );
        }
        Some(guard)
    } else {
        None
    })
}

/// Round-trip proof: parse the NZB we just wrote, download every segment
/// back through the engine's connection pool from the SAME server, decode
/// and reassemble to temp files, then compare SHA-256 against the sources.
async fn verify(
    server: &ServerConfig,
    args: &PostArgs,
    plan: &[nzbkit::post::PlanFile],
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};

    info!(target: "verify", "re-downloading the post from {} …", server.host);
    // Freshly posted articles can take a moment to become retrievable
    // even on the posting server.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let xml = std::fs::read(&args.nzb)?;
    let nzb = nzbkit::nzb::Nzb::parse(&xml).context("parsing the emitted NZB")?;

    // Keyed on the POSTED name, which is what a subject quotes and
    // therefore what `filename_hint` gives back. Under obfuscation that
    // is the random token and the real name is nowhere on the wire -
    // which is the property being verified, so keying on the real name
    // would fail every obfuscated run by construction.
    let by_name: std::collections::HashMap<&str, &nzbkit::post::PlanFile> =
        plan.iter().map(|f| (f.posted.as_str(), f)).collect();

    // message-id → (per-file temp handle). Preallocate one temp file per
    // posted file, next to the NZB so cleanup is obvious on failure.
    let tmp_dir = args.nzb.with_extension("verify.tmp");
    // Exclusive, not `create_dir_all`: this path is derived from a
    // user-supplied NZB name, every child is opened with a truncating
    // create, and the whole directory is `remove_dir_all`'d at the end.
    // A directory that already exists is someone else's - a crashed
    // earlier verify, a concurrent one, or unrelated data - and nothing
    // here proves otherwise, so refuse instead of truncating and then
    // recursively deleting it.
    std::fs::create_dir(&tmp_dir).map_err(|e| {
        anyhow::anyhow!(
            "verify scratch directory {} already exists or cannot be created ({e}) - \
             remove it and re-run",
            tmp_dir.display()
        )
    })?;
    // (posted name, real name, source path, temp handle, size)
    let mut files: Vec<(String, String, PathBuf, std::fs::File, u64)> = Vec::new();
    let mut id_to_file: std::collections::HashMap<String, usize> = Default::default();
    let mut reqs: Vec<ArticleReq> = Vec::new();
    for f in &nzb.files {
        let name = f
            .filename_hint()
            .ok_or_else(|| anyhow::anyhow!("NZB subject carries no filename: {}", f.subject))?;
        let src = by_name
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("NZB names {name:?} which was not in the plan"))?;
        let tmp_path = tmp_dir.join(name);
        let tmp = std::fs::File::create(&tmp_path)?;
        tmp.set_len(src.size)?;
        let idx = files.len();
        // The REAL name in the report line: a column of random tokens
        // tells the operator nothing about which file failed.
        files.push((
            name.to_string(),
            src.rel.clone(),
            src.path.clone(),
            tmp,
            src.size,
        ));
        for seg in &f.segments {
            let bracketed = format!("<{}>", seg.message_id);
            id_to_file.insert(bracketed.clone(), idx);
            reqs.push(ArticleReq::fresh(bracketed));
        }
    }
    let total = reqs.len();

    let pool_cfg = PoolConfig {
        connections: args.connections.clamp(1, 16),
        window: 4,
        ..PoolConfig::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(64);
    let servers = vec![(server.clone(), pool_cfg)];
    let fetcher = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });

    let mut got = 0usize;
    let mut problems: Vec<String> = Vec::new();
    while let Some(outcome) = rx.recv().await {
        match outcome {
            FetchOutcome::Done { id, raw } => {
                let Some(&idx) = id_to_file.get(&*id) else {
                    continue;
                };
                match nzbkit::yenc::decode(&raw) {
                    Ok(dec) => {
                        nzbkit::disk::write_all_at(&files[idx].3, &dec.data, dec.offset())?;
                        got += 1;
                    }
                    Err(e) => problems.push(format!("{id}: decode: {e}")),
                }
            }
            FetchOutcome::Missing { id, .. } => problems.push(format!("{id}: missing (430)")),
            // `code` deliberately unread here: this list is a human
            // diagnostic, and the sentence carries the OS's own words
            // for what happened, which is the more useful half of the
            // pair for someone reading a CLI run.
            FetchOutcome::Failed { id, error, .. } => problems.push(format!("{id}: {error}")),
        }
    }
    let _ = fetcher.await;
    info!(target: "verify", "fetched {got}/{total} articles");

    let mut failed = !problems.is_empty();
    for p in &problems {
        info!(target: "verify", "problem: {p}");
    }
    for (posted, real, src, tmp, _) in files {
        drop(tmp); // close the write handle before hashing
        let want = nzbkit::post::sha256_file(&src)?;
        let have = nzbkit::post::sha256_file(&tmp_dir.join(&posted))?;
        let ok = want == have;
        failed |= !ok;
        info!(
            target: "verify",
            "{real}: {}",
            if ok {
                format!("OK sha256={want}")
            } else {
                format!("MISMATCH source={want} downloaded={have}")
            }
        );
    }
    if failed {
        anyhow::bail!(
            "verification FAILED - temp downloads kept in {} for inspection",
            tmp_dir.display()
        );
    }
    std::fs::remove_dir_all(&tmp_dir)?;
    info!(target: "verify", "all files match - round trip proven");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(servers: Vec<ServerConfig>) -> Config {
        // Config has no public constructor shortcut; round-trip via JSON.
        let json = serde_json::json!({
            "servers": servers,
        });
        serde_json::from_value(json).unwrap()
    }

    fn srv(host: &str, port: u16, enabled: bool) -> ServerConfig {
        ServerConfig {
            host: host.into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 4,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
            address_family: Default::default(),
            tls_hostname: None,
            warm_reserve: None,
        }
    }

    #[test]
    fn server_selection_is_strict() {
        let c = cfg(vec![
            srv("news.alpha.example", 563, true),
            srv("news.beta.example", 563, true),
            srv("news.beta.example", 119, true),
            srv("news.off.example", 563, false),
        ]);
        // Exact single host match, case-insensitive.
        assert_eq!(
            select_server(&c, "News.Alpha.Example").unwrap().host,
            "news.alpha.example"
        );
        // No match: hard error listing candidates.
        let e = select_server(&c, "news.nope.example")
            .unwrap_err()
            .to_string();
        assert!(e.contains("matches no configured server"), "{e}");
        assert!(e.contains("news.alpha.example:563"), "{e}");
        // Ambiguous host: must disambiguate with host:port.
        let e = select_server(&c, "news.beta.example")
            .unwrap_err()
            .to_string();
        assert!(e.contains("disambiguate"), "{e}");
        assert_eq!(
            select_server(&c, "news.beta.example:119").unwrap().port,
            119
        );
        // Disabled server: refused even when named explicitly.
        let e = select_server(&c, "news.off.example")
            .unwrap_err()
            .to_string();
        assert!(e.contains("disabled"), "{e}");
    }

    /// The temp path is derived from --nzb alone, so two posts to the same
    /// destination race for it. The claim is exclusive: an existing temp
    /// stops the run before anything is uploaded, whether it holds an
    /// earlier rescue index or is just another run's fresh (empty) claim.
    #[tokio::test]
    async fn an_existing_tmp_claim_stops_the_run_before_it_posts() {
        let dir = std::env::temp_dir().join(format!("nzbfast-postclaim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("corpus.bin"), vec![7u8; 4_000]).unwrap();
        let config_path = dir.join("config.json");
        // Port 1 is never dialled: the claim is checked before any connection.
        std::fs::write(
            &config_path,
            "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
        )
        .unwrap();
        let nzb_path = dir.join("posted.nzb");
        let tmp = PathBuf::from(format!("{}.nzbtmp", nzb_path.display()));
        let args = || PostArgs {
            paths: vec![dir.join("corpus.bin")],
            post_server: "127.0.0.1:1".into(),
            nzb: nzb_path.clone(),
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.invalid".into(),
            msgid_domain: "nzbfast.invalid".into(),
            article_size: 1_000,
            title: None,
            connections: 1,
            verify: false,
            allow_empty: false,
            obfuscate: false,
            obfuscate_empty_name: false,
            par2: None,
            par2_block_size: None,
            par2_base: None,
        };

        // An EMPTY temp is another run's claim - refuse (this used to proceed
        // and later rename over whatever that run published).
        std::fs::write(&tmp, b"").unwrap();
        let err = format!("{:#}", run(&config_path, args()).await.unwrap_err());
        assert!(err.contains("is already claimed"), "{err}");
        assert!(err.contains("another `nzbfast post`"), "{err}");

        // A NON-EMPTY temp is a stranded rescue index - different guidance.
        std::fs::write(&tmp, b"<nzb/>").unwrap();
        let err = format!("{:#}", run(&config_path, args()).await.unwrap_err());
        assert!(err.contains("already holds the retrieval index"), "{err}");

        // Neither refusal touched the record it was protecting.
        assert_eq!(std::fs::read(&tmp).unwrap(), b"<nzb/>");
        assert!(!nzb_path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A rescue index never overwrites a file it does not own: if the claim
    /// is gone, the rescue lands under a name unique to this process.
    #[test]
    fn a_rescue_never_overwrites_a_claim_it_lost() {
        let dir = std::env::temp_dir().join(format!("nzbfast-postrescue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let claim = dir.join("posted.nzb.nzbtmp");

        // Claim held: the rescue goes straight into it.
        std::fs::write(&claim, b"").unwrap();
        assert_eq!(write_rescue(&claim, "<nzb>mine</nzb>").unwrap(), claim);
        assert_eq!(std::fs::read_to_string(&claim).unwrap(), "<nzb>mine</nzb>");

        // Claim moved out from under us: the rescue lands elsewhere rather
        // than re-creating (and later being mistaken for) the lost temp.
        let published = dir.join("posted.nzb");
        std::fs::rename(&claim, &published).unwrap();
        let at = write_rescue(&claim, "<nzb>later</nzb>").unwrap();
        assert!(
            at.to_string_lossy()
                .ends_with(&format!(".{}", std::process::id())),
            "{}",
            at.display()
        );
        assert_eq!(std::fs::read_to_string(&at).unwrap(), "<nzb>later</nzb>");
        assert_eq!(
            std::fs::read_to_string(&published).unwrap(),
            "<nzb>mine</nzb>"
        );

        // Someone else's rescue index now sits at the claim path (our claim
        // was cleared away mid-run and a second run left its own record
        // there). It has bytes in it, so it is never truncated - ours goes
        // to the next free name of our own.
        std::fs::write(&claim, b"<nzb>theirs</nzb>").unwrap();
        let at2 = write_rescue(&claim, "<nzb>ours</nzb>").unwrap();
        assert_ne!(at2, claim);
        assert_eq!(
            at2,
            PathBuf::from(format!("{}.{}.1", claim.display(), std::process::id()))
        );
        assert_eq!(std::fs::read_to_string(&at2).unwrap(), "<nzb>ours</nzb>");
        assert_eq!(
            std::fs::read_to_string(&claim).unwrap(),
            "<nzb>theirs</nzb>"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A failure that put NOTHING on the server has no Message-IDs to
    /// protect, so the claim it took is handed back. Leaving that empty file
    /// behind would meet the retry - one transient refusal later - with
    /// "another post is probably writing", which is simply untrue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_post_that_never_landed_gives_its_claim_back() {
        let srv = nzbkit::mock::MockServer::start(
            Default::default(),
            nzbkit::mock::Chaos {
                post: nzbkit::mock::PostChaos {
                    // Rejected from the very first article: nothing is stored.
                    reject_441: Some("posting failed".into()),
                    reject_after: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postnone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("corpus.bin"), vec![9u8; 3_000]).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();
        let nzb_path = dir.join("posted.nzb");
        let args = || PostArgs {
            paths: vec![dir.join("corpus.bin")],
            post_server: format!("127.0.0.1:{}", srv.addr.port()),
            nzb: nzb_path.clone(),
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.invalid".into(),
            msgid_domain: "nzbfast.invalid".into(),
            article_size: 1_000,
            title: None,
            connections: 1,
            verify: false,
            allow_empty: false,
            obfuscate: false,
            obfuscate_empty_name: false,
            par2: None,
            par2_block_size: None,
            par2_base: None,
        };
        let tmp = PathBuf::from(format!("{}.nzbtmp", nzb_path.display()));

        let err = format!("{:#}", run(&config_path, args()).await.unwrap_err());
        assert!(err.contains("posting failed"), "{err}");
        assert!(
            !tmp.exists(),
            "the claim outlived a run that posted nothing"
        );
        assert!(!nzb_path.exists());

        // So the retry gets as far as the server, instead of being refused
        // by the last run's leftovers.
        let err = format!("{:#}", run(&config_path, args()).await.unwrap_err());
        assert!(!err.contains("already claimed"), "{err}");
        assert!(!err.contains("already holds the retrieval index"), "{err}");
        assert!(!tmp.exists(), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The whole CLI path against the mock server: run() with --verify
    /// posts real files, writes a parseable NZB, re-downloads through the
    /// pool and passes the hash comparison.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_posts_and_verifies_against_the_mock() {
        let srv =
            nzbkit::mock::MockServer::start(Default::default(), nzbkit::mock::Chaos::default())
                .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postcmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..250_000).map(|i| (i * 31 + i / 255) as u8).collect();
        std::fs::write(dir.join("corpus-a.bin"), &data).unwrap();
        std::fs::write(dir.join("corpus-b.bin"), &data[..70_000]).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();

        let nzb_path = dir.join("posted.nzb");
        run(
            &config_path,
            PostArgs {
                paths: vec![dir.join("corpus-a.bin"), dir.join("corpus-b.bin")],
                post_server: format!("127.0.0.1:{}", srv.addr.port()),
                nzb: nzb_path.clone(),
                group: "alt.binaries.test".into(),
                from: "corpus@nzbfast.invalid".into(),
                msgid_domain: "nzbfast.invalid".into(),
                article_size: 100_000,
                title: Some("post cmd e2e".into()),
                connections: 3,
                verify: true,
                allow_empty: false,
                obfuscate: false,
                obfuscate_empty_name: false,
                par2: None,
                par2_block_size: None,
                par2_base: None,
            },
        )
        .await
        .expect("post + verify");

        let nzb = nzbkit::nzb::Nzb::parse(&std::fs::read(&nzb_path).unwrap()).unwrap();
        assert_eq!(nzb.files.len(), 2);
        assert_eq!(nzb.files.iter().map(|f| f.segments.len()).sum::<usize>(), 4);
        // Verify's temp dir is cleaned up on success.
        assert!(!nzb_path.with_extension("verify.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The no-RAR CLI path: `--obfuscate --par2` posts a payload whose
    /// wire names say nothing, builds and posts the recovery set that
    /// carries the real ones, and still passes `--verify` - which is the
    /// non-obvious half, because verify has to match a downloaded file
    /// back to its source through the RANDOM posted name and would
    /// otherwise fail every obfuscated run by construction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_posts_an_obfuscated_set_with_its_par2_and_verifies_it() {
        let srv =
            nzbkit::mock::MockServer::start(Default::default(), nzbkit::mock::Chaos::default())
                .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postcmd-obf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("release/Sub")).unwrap();
        let data: Vec<u8> = (0..180_000).map(|i| (i * 17 + i / 251) as u8).collect();
        std::fs::write(dir.join("release/Feature.2024.mkv"), &data).unwrap();
        std::fs::write(dir.join("release/Sub/Feature.2024.srt"), &data[..4_000]).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();

        let nzb_path = dir.join("obf.nzb");
        let args = || PostArgs {
            paths: vec![dir.join("release")],
            post_server: format!("127.0.0.1:{}", srv.addr.port()),
            nzb: nzb_path.clone(),
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.invalid".into(),
            msgid_domain: "nzbfast.invalid".into(),
            article_size: 60_000,
            title: None,
            connections: 2,
            verify: true,
            allow_empty: false,
            obfuscate: true,
            obfuscate_empty_name: false,
            par2: Some(10),
            par2_block_size: Some(4096),
            par2_base: None,
        };
        run(&config_path, args()).await.expect("obfuscated post");

        let xml = std::fs::read_to_string(&nzb_path).unwrap();
        assert!(
            !xml.contains("Feature.2024"),
            "the NZB spells a real name:\n{xml}"
        );
        // The recovery set IS on the wire and IS findable - it is the
        // only thing carrying the names.
        assert!(xml.contains(".par2"), "no recovery set in the NZB:\n{xml}");
        // Both scratch directories are gone on success.
        assert!(!nzb_path.with_extension("par2.tmp").exists());
        assert!(!nzb_path.with_extension("verify.tmp").exists());

        // And the safety rule: obfuscation with no carrier is refused
        // before a byte moves, rather than publishing nameless articles.
        let mut naked = args();
        naked.par2 = None;
        naked.nzb = dir.join("naked.nzb");
        let err = format!("{:#}", run(&config_path, naked).await.unwrap_err());
        assert!(err.contains("need a carrier"), "wrong refusal: {err}");
        assert!(!dir.join("naked.nzb").exists(), "it published anyway");

        // A PAR2 build that fails sits BETWEEN the NZB claim and the
        // first byte, so it has to give the claim back - otherwise the
        // rerun meets "another post is probably writing" over an empty
        // file this run abandoned, and no rerun can ever get past it.
        let mut bad = args();
        bad.nzb = dir.join("badspec.nzb");
        bad.par2_block_size = Some(6); // not a multiple of 4
        let err = format!("{:#}", run(&config_path, bad).await.unwrap_err());
        assert!(err.contains("multiple of 4"), "wrong refusal: {err}");
        assert!(
            !dir.join("badspec.nzb.nzbtmp").exists(),
            "the NZB claim was abandoned - the rerun is now blocked forever"
        );
        assert!(
            !dir.join("badspec.par2.tmp").exists(),
            "scratch left behind"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An upload that aborts partway has already made articles public. The
    /// run must fail, and it must leave their Message-IDs on disk - that
    /// index is the operator's only handle on what they just posted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_post_leaves_the_message_ids_that_already_landed() {
        let srv = nzbkit::mock::MockServer::start(
            Default::default(),
            nzbkit::mock::Chaos {
                post: nzbkit::mock::PostChaos {
                    reject_441: Some("posting failed".into()),
                    reject_after: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let dir = std::env::temp_dir().join(format!("nzbfast-postabort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..5_000).map(|i| (i * 31 + i / 255) as u8).collect();
        std::fs::write(dir.join("corpus.bin"), &data).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .unwrap();
        let nzb_path = dir.join("posted.nzb");
        let args = || PostArgs {
            paths: vec![dir.join("corpus.bin")],
            post_server: format!("127.0.0.1:{}", srv.addr.port()),
            nzb: nzb_path.clone(),
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.invalid".into(),
            msgid_domain: "nzbfast.invalid".into(),
            article_size: 1_000,
            title: None,
            connections: 1,
            verify: false,
            allow_empty: false,
            obfuscate: false,
            obfuscate_empty_name: false,
            par2: None,
            par2_block_size: None,
            par2_base: None,
        };

        let err = run(&config_path, args()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("2 articles are posted or may be posted"),
            "{msg}"
        );

        // The rescue index is a real NZB listing exactly what landed.
        let tmp = PathBuf::from(format!("{}.nzbtmp", nzb_path.display()));
        let rescue = nzbkit::nzb::Nzb::parse(&std::fs::read(&tmp).unwrap())
            .expect("the rescue index parses as an NZB");
        assert_eq!(
            rescue.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            2
        );
        // The real NZB was never written - a failed post publishes nothing.
        assert!(!nzb_path.exists());

        // And a second run refuses rather than truncating that record.
        let err = run(&config_path, args()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("already holds the retrieval index"),
            "{err:#}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
