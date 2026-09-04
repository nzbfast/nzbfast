//! TODO 218: auto-assigning a category from the NZB itself - its
//! `<meta type="category">` and its newsgroups - when an add names
//! none. SABnzbd's "Indexer Categories / Groups", which a reporter
//! moving over from SAB missed first. Also home to the older §129 2b
//! per-category test (dir, priority, script), moved here by the size
//! gate.
//!
//! A child of daemon_tests, named for its file so size-gate.py's
//! CFG_TEST_MOD resolver reads it as test code; `use super::*` brings
//! the harness.

use super::*;

fn nzb_with(meta: &str, group: &str, msgid: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <head>{meta}</head>\
         <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
         <groups><group>{group}</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{msgid}@x</segment>\
         </segments></file></nzb>"
    )
}

fn job_cat(d: &Daemon, id: &str) -> String {
    let q = d.queue.lock_ok();
    q.iter()
        .find(|j| j.lock_ok().nzo_id == *id)
        .map(|j| j.lock_ok().category.clone())
        .unwrap()
}

#[test]
fn infer_category_from_meta_name_then_groups_patterns() {
    with_daemon("infercat", |d| {
        use super::CatMeta;
        d.register_cat("tv");
        d.register_cat("Films");
        d.cat_meta.lock_ok().insert(
            "Films".into(),
            CatMeta {
                groups: "alt\\.binaries\\.movies, hdtv-x264".into(),
                ..Default::default()
            },
        );
        let add = |nzb: String, cat: &str| {
            d.enqueue(
                nzb.as_bytes(),
                "Rel.nzb",
                cat,
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
            .unwrap()
        };
        // 1. Meta category equal to a category's name, case-insensitive,
        //    with no pattern configured at all.
        let id = add(
            nzb_with(
                "<meta type=\"category\">TV</meta>",
                "alt.binaries.teevee",
                "m1",
            ),
            "",
        );
        assert_eq!(job_cat(d, &id), "tv", "meta name match needs no config");
        // 2. No meta: a category's pattern matches a newsgroup.
        let id = add(nzb_with("", "alt.binaries.movies.divx", "m2"), "");
        assert_eq!(job_cat(d, &id), "Films", "groups pattern on a newsgroup");
        // 3. A pattern on a meta category that is NOT a category name.
        let id = add(
            nzb_with(
                "<meta type=\"category\">Movies > HDTV-x264</meta>",
                "a.b.x264",
                "m3",
            ),
            "",
        );
        assert_eq!(job_cat(d, &id), "Films", "groups pattern on the meta value");
        // 4. Nothing matches: uncategorised, as before.
        let id = add(nzb_with("", "alt.binaries.sounds", "m4"), "");
        assert_eq!(job_cat(d, &id), "", "no match = no category");
        // 5. An explicit cat= is never second-guessed, even when the
        //    NZB says otherwise.
        let id = add(
            nzb_with(
                "<meta type=\"category\">tv</meta>",
                "alt.binaries.movies",
                "m5",
            ),
            "books",
        );
        assert_eq!(job_cat(d, &id), "books", "explicit category wins");
    });
}

/// §129 2b: real per-category behavior - the category's default
/// priority fills a default add (explicit wins), its dir renames the
/// subfolder (contained, sanitized), and script resolution runs
/// job-override, then category, then global.
#[test]
fn cat_meta_priority_dir_and_script_apply() {
    with_daemon("catmeta", |d| {
        use super::CatMeta;
        d.cat_meta.lock_ok().insert(
            "tv".into(),
            CatMeta {
                dir: "series/current".into(),
                priority: Some(1),
                script: "/scripts/tv.py".into(),
                nzb_name: None,
                groups: String::new(),
            },
        );
        // dir: the category's subfolder is renamed, nested, contained.
        let base = d.base_out_dir("tv", "job");
        assert_eq!(
            base,
            crate::naming::out_dir(d)
                .join("series")
                .join("current")
                .join("job")
        );
        // A traversal in the meta dir cannot escape the root.
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "../../evil".into();
        assert_eq!(
            d.base_out_dir("tv", "job"),
            crate::naming::out_dir(d).join("evil").join("job")
        );
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "series/current".into();
        // No meta = the old shape, untouched.
        assert_eq!(
            d.base_out_dir("movies", "job"),
            crate::naming::out_dir(d).join("movies").join("job")
        );
        assert_eq!(
            d.base_out_dir("", "job"),
            crate::naming::out_dir(d).join("job")
        );

        // priority: fills the default, loses to an explicit one.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                   <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                   <groups><group>g</group></groups><segments>\
                   <segment bytes=\"1000\" number=\"1\">cm1@x</segment>\
                   </segments></file></nzb>";
        let id = d
            .enqueue(
                nzb.as_bytes(),
                "Alpha.2026.nzb",
                "tv",
                -100,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
            .unwrap();
        let nzb2 = nzb.replace("cm1@x", "cm2@x");
        let id2 = d
            .enqueue(
                nzb2.as_bytes(),
                "Beta.2026.nzb",
                "tv",
                -1,
                None,
                None,
                "test",
                false,
            )
            .map(|e| e.nzo_id)
            .unwrap();
        {
            let q = d.queue.lock_ok();
            let prio = |id: &str| {
                q.iter()
                    .find(|j| j.lock_ok().nzo_id == *id)
                    .map(|j| j.lock_ok().priority)
                    .unwrap()
            };
            assert_eq!(prio(&id), 1, "category default fills a default add");
            assert_eq!(prio(&id2), -1, "an explicit priority wins");
        }

        // script resolution order.
        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .unwrap();
        let one = |p: &str| vec![std::path::PathBuf::from(p)];
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/tv.py"),
            "category script beats the (unset) global"
        );
        *d.scripts.lock_ok() = one("/scripts/global.py");
        job.lock_ok().category = "movies".into();
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/global.py"),
            "no category script falls back to the global one"
        );
        job.lock_ok().script_override = "/scripts/mine.py".into();
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/mine.py"),
            "the job's own script= wins"
        );
        // §192: a rung is a CHAIN, and the first rung with anything
        // wins WHOLE - the category's chain does not append to the
        // global one.
        job.lock_ok().script_override = "/scripts/a.py,/scripts/b.py".into();
        assert_eq!(
            d.resolve_scripts(&job),
            vec![
                std::path::PathBuf::from("/scripts/a.py"),
                std::path::PathBuf::from("/scripts/b.py"),
            ],
            "the override chain runs in the order it was written"
        );
        job.lock_ok().script_override = "None".into();
        assert!(
            d.resolve_scripts(&job).is_empty(),
            "script=None means none at all"
        );

        // record_add_params: pp + script land on the job. A bare name
        // is what a SAB client sends back from mode=get_scripts, so it
        // resolves through known_scripts to the real path - stored
        // verbatim it became a cwd-relative path that ran nothing.
        // (§129 4a: record_add_params FILLS, never clobbers - at add
        // time these fields are empty unless the pre-queue hook set
        // them, and the hook outranks the request. Clear the values the
        // resolve_scripts cases above planted.)
        {
            let g = job_by(d, &id);
            let mut g = g.lock_ok();
            g.script_override = String::new();
            g.sab_pp = None;
        }
        d.record_add_params(&id, Some("1"), Some("tv.py"), false);
        {
            let g = job_by(d, &id);
            let g = g.lock_ok();
            assert_eq!(g.sab_pp, Some(1));
            assert_eq!(g.script_override, "/scripts/tv.py");
        }
        // ...and known_scripts is exactly what get_scripts offers:
        // global + per-category, deduped by basename, global first.
        let names: Vec<String> = d.known_scripts().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["global.py", "tv.py"]);
        // An unknown name is a logged compatibility note, never a
        // stored override - the category/global ladder stays in charge.
        // (Also the fill-only rule doing its other job: refusing can
        // never become a way to CLEAR an existing override.)
        d.record_add_params(&id, None, Some("ghost.py"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // §129 4a: fill-only in general - once set (at add time that
        // means the pre-queue hook set it), the request's own script=
        // does not displace it. The hook outranks the request, SAB
        // pre-queue semantics.
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/scripts/tv.py",
            "a planted override survives the request's script="
        );
        let clear = || job_by(d, &id).lock_ok().script_override = String::new();
        // A path-bearing value is operator intent and stays as written.
        clear();
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py"
        );
        // ...but ONLY for a full-key caller. `addfile`/`addurl` are on
        // the add-only allowlist and `resolve_scripts` hands
        // `script_override` straight to `Command::new` on the job tail,
        // so accepting a path here let the NZB key - which ships to
        // browser push extensions - choose which program the daemon
        // runs. The previous override must survive untouched: refusing
        // must not become a way to CLEAR someone else's setting.
        d.record_add_params(&id, None, Some("/tmp/pwn.sh"), true);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py",
            "an add-only credential may not choose the program to run"
        );
        // A configured name is still fine on the add-only key: it can
        // only select something the operator already installed.
        clear();
        d.record_add_params(&id, None, Some("tv.py"), true);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // SAB's own null still suppresses the whole ladder.
        clear();
        d.record_add_params(&id, None, Some("None"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "None");
        assert!(d.resolve_scripts(&job_by(d, &id)).is_empty());
    });
}
