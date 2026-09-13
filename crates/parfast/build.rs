//! Stamp the commit this binary was built from into `-VV`.
//!
//! WHY THIS EXISTS, and it cost a benchmark round to learn. `-V` prints
//! `parfast version <CARGO_PKG_VERSION>`, which is bumped per RELEASE and is
//! therefore constant across every commit in a release cycle. A sha256 names
//! the FILE; until this build script, nothing named the SOURCE. On 10 Sep 2026
//! two bench boxes were measured on binaries five commits stale - among them
//! the Forney back-substitution gate recalibration and a `v` change that cut
//! recovery-volume reads from 2.30 GB to 0.10 GB - and neither binary could say
//! so. One had been built from an exported tree with no `.git` in it at all, so
//! its commit was not merely unrecorded, it was unrecoverable.
//!
//! Resolution order, and the FIRST entry is the one a bench box actually needs,
//! because a bench box builds from an export and has no git history to ask:
//!
//!   1. `NZBFAST_BUILD_COMMIT`, passed by whatever produced the export
//!   2. `git rev-parse`, for an ordinary checkout, with a `-dirty` suffix when
//!      the working tree has uncommitted changes - a benchmark built from a
//!      dirty tree is not reproducible and should say so on its own
//!   3. `unknown`, said plainly rather than guessed at
//!
//! THE STALE-STAMP TRAP, which would be worse than no stamp at all: emitting
//! any `cargo:rerun-if-*` line switches cargo from "rerun when the package
//! changes" to "rerun only for these", so a script that watched nothing but the
//! environment would keep printing the FIRST commit it ever saw. The watches
//! below are resolved through `git rev-parse --git-path`, which answers
//! correctly inside a worktree (where `.git` is a file, not a directory), and
//! cover both the detached case (HEAD itself moves) and the on-a-branch case
//! (HEAD is unchanged text and the ref file moves under it).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Watch the files that move when a commit lands, so the stamp cannot go stale.
fn watch_git_refs() {
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    // On a branch, HEAD's own bytes never change; the ref it names does.
    if let Some(refname) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &refname])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    // A packed ref has no loose file, so watch the pack too.
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        println!("cargo:rerun-if-changed={packed}");
    }
}

fn from_git() -> Option<String> {
    let mut id = git(&["rev-parse", "--short=12", "HEAD"])?;
    // `--untracked-files=no` is load-bearing, not a tidy-up. This repo is a
    // SHARED CHECKOUT that several sessions work at once, so untracked files
    // belonging to other lanes - research logs, scratch output - are present
    // almost always. Counting those as dirty would append `-dirty` to every
    // binary anyone ever built here, and a marker that is always on says
    // nothing. Dirty here means what it needs to mean: a TRACKED file differs
    // from the commit named beside it, so the source is not what the stamp
    // claims. (An untracked `.rs` only reaches the build through a `mod` line
    // in a tracked file, which this does see.)
    // ref-gate: the `.rs` above is the file EXTENSION in prose - "an untracked
    // .rs" is any Rust file at all, not a path to one - so there is no file
    // for it to resolve to and never was. Do not answer this by naming a
    // real path: the sentence is about the whole class.
    //
    // `git()` returns None for empty output, and a clean tree is exactly what
    // `status --porcelain` says nothing about - so Some here means dirty.
    if git(&["status", "--porcelain", "--untracked-files=no"]).is_some() {
        id.push_str("-dirty");
    }
    Some(id)
}

fn main() {
    println!("cargo:rerun-if-env-changed=NZBFAST_BUILD_COMMIT");
    watch_git_refs();
    let commit = std::env::var("NZBFAST_BUILD_COMMIT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(from_git)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PARFAST_BUILD_COMMIT={commit}");
}
