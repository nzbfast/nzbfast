//! Peak-RSS rig for the RAR 5 write policy's accounting of each member's
//! match-finder tree, which bounds how many members encode side by side.
//!
//! Publishes a process budget the way an entry point does, then runs
//! postfast's own posting path (`generate_over_with`, the call `post`
//! makes) over real files cut into equal members, into ONE RAR 5 volume.
//! Read the peak with `/usr/bin/time -l`; this prints what the peak has
//! to be read against. The `stored` arm is the same payload and planes
//! with no encoder. It is NOT a floor for the compressed arms: it holds
//! a whole-size archive where they hold a packed one, so compare a
//! compressed arm against itself across builds or budgets, not against it.
//!
//! The writer's default dictionary sits under the 4 MiB the tree arms at,
//! so set `MEMBER_TREE_RSS_DICT_MIB` (`post --dictionary`, in MiB) to 4 or
//! more to exercise the tree at all.
//!
//! usage: member_tree_rss <budget MiB> <member MiB> <count> <lazy|optimal|stored> <corpus file>...
//!
//! The corpus files are concatenated and cut into `count` members of
//! `member MiB` each (the concatenation must be long enough). Set
//! `MEMBER_TREE_RSS_DUMP=<dir>` to write the posted volumes there.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: member_tree_rss <budget MiB> <member MiB> <count> <lazy|optimal|stored> <corpus>..."
        );
        std::process::exit(2);
    }
    let budget_mib: u64 = args[1].parse().expect("budget MiB");
    let member_bytes = args[2].parse::<usize>().expect("member MiB") << 20;
    let count: usize = args[3].parse().expect("count");
    let (kind, optimal_parse) = match args[4].as_str() {
        "lazy" => ("rar-compressed", false),
        "optimal" => ("rar-compressed", true),
        "stored" => ("rar-stored", false),
        other => panic!("arm is lazy, optimal or stored, not {other}"),
    };
    let mut corpus = Vec::new();
    for path in &args[5..] {
        corpus.extend_from_slice(&std::fs::read(path).expect("read corpus"));
        if corpus.len() >= member_bytes * count {
            break;
        }
    }
    assert!(
        corpus.len() >= member_bytes * count,
        "corpus is {} bytes, the members need {}",
        corpus.len(),
        member_bytes * count
    );
    let payload: Vec<Vec<u8>> = corpus[..member_bytes * count]
        .chunks(member_bytes)
        .map(<[u8]>::to_vec)
        .collect();
    drop(corpus);

    let content = if kind == "rar-stored" {
        "noise"
    } else {
        "compressible"
    };
    let mut files = String::new();
    for i in 0..count {
        files.push_str(&format!(
            "  {{ name = \"m{i:03}.bin\", bytes = {member_bytes}, content = \"{content}\" }},\n"
        ));
    }
    let toml = format!(
        "[layout]\nname = \"member-tree-rss\"\nseed = 349\n\n[source]\nfiles = [\n{files}]\n\n\
         [container]\nkind = \"{kind}\"\n\n[expect]\ncomplete = true\n\n\
         [expect.ladder]\nreaches = \"\"\n"
    );
    let profile = postfast::Profile::parse(&toml).expect("profile");

    let budget = nzbkit::mem::MemBudget::with_total(budget_mib << 20);
    nzbkit::mem::set_process_budget(budget);
    let policy = nzbkit::mem::process_budget().rar_write_policy();

    // `post --dictionary <bytes>`, here in MiB; unset is the writer's default.
    let dictionary = std::env::var("MEMBER_TREE_RSS_DICT_MIB")
        .ok()
        .map(|v| v.parse::<u64>().expect("MEMBER_TREE_RSS_DICT_MIB is MiB") << 20);

    let started = std::time::Instant::now();
    let layout = postfast::layout::generate_over_with(
        &profile,
        payload,
        postfast::Packing {
            optimal_parse,
            dictionary,
        },
    )
    .expect("layout");
    let wall = started.elapsed().as_secs_f64();

    let dump = std::env::var_os("MEMBER_TREE_RSS_DUMP").map(std::path::PathBuf::from);
    let mut crc = crc32fast::Hasher::new();
    let mut bytes = 0usize;
    // The posted files in order (`articles` is a map, so hashing it would
    // hash an iteration order).
    for (name, body) in &layout.files {
        crc.update(name.as_bytes());
        crc.update(body);
        bytes += body.len();
        if let Some(dir) = &dump {
            std::fs::write(dir.join(name), body).expect("dump volume");
        }
    }
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "budget_mib={budget_mib} member_mib={} count={count} arm={} policy_working_mib={} \
         policy_max_dict={} cores={} posted_bytes={bytes} crc={:08x} wall_s={wall:.1}",
        member_bytes >> 20,
        args[4],
        policy.working_memory_limit >> 20,
        policy.max_dictionary,
        std::thread::available_parallelism().map_or(1, usize::from),
        crc.finalize(),
    )
    .unwrap();
}
