//! Diagnostic: map RAR volume headers from on-disk files and print what
//! the arithmetic gate would see.
//! Usage: rarprobe [--head N] [--password PW] <files...>

use nzbkit::rar::{
    ArchiveMap, ArithGate, EntryCrypt, VolumeMapper, feed_headers_incrementally_pub,
};

/// Truncate for display without splitting a character. A RAR4 name is
/// decoded UTF-16 and a RAR5 one is raw UTF-8, so a non-ASCII name is
/// routine here; slicing it by a raw byte count panics the probe on the
/// very archives it exists to diagnose (measured 23 Aug 2026 on a
/// WinRAR-written archive whose member is named in fullwidth Latin -
/// three bytes per character, so the 40-byte cap landed mid-character).
fn clip(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn main() {
    // --head N: feed only the first N bytes (a partially-downloaded
    // volume is sparse - the incremental feeder would walk into holes
    // and report artifact blockers).
    // --password PW: what the extractor would see WITH a key. Without it
    // an encrypted set reports only its blocker, and a header-encrypted
    // one reports nothing at all - which is the whole question when a
    // locked set is the thing being debugged.
    // --declared N / --declared -K: map with the size the POST declares
    // rather than the file's physical length. The mapper's volume bound
    // is the poster's `=ybegin size=` field, which nothing verifies (see
    // `yenc::check_part_geometry`), so "does this set map?" and "does
    // this set map at the size the post claims?" are different
    // questions - TODO 118 item 2 is the second one. A leading `-`
    // means "physical MINUS K", which is how a declaration that
    // understates is probed without knowing each volume's length.
    // The volume-bounds refusal names its two terms through a tracing
    // event (`rar::VolumeMapper::fail_volume_bound`), and an example
    // binary that installs no sink prints nothing - which would make
    // this probe silent on the one question `--declared` exists to ask.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut head: Option<usize> = None;
    let mut password: Option<String> = None;
    let mut declared: Option<i64> = None;
    while let Some(flag) = args.first().cloned() {
        match flag.as_str() {
            "--head" => {
                args.remove(0);
                head = Some(args.remove(0).parse().unwrap());
            }
            "--password" => {
                args.remove(0);
                password = Some(args.remove(0));
            }
            "--declared" => {
                args.remove(0);
                declared = Some(args.remove(0).parse().unwrap());
            }
            _ => break,
        }
    }
    let mut mappers: Vec<VolumeMapper> = Vec::new();
    for p in &args {
        let Ok(mut f) = std::fs::File::open(p) else {
            eprintln!("{p}: open failed");
            continue;
        };
        let physical = f.metadata().map(|m| m.len()).unwrap_or(0);
        let size = match declared {
            None => physical,
            Some(d) if d >= 0 => d as u64,
            Some(d) => physical.saturating_sub(d.unsigned_abs()),
        };
        let mut m =
            VolumeMapper::with_password(size, password.as_deref().map(std::sync::Arc::from));
        if let Some(n) = head {
            use std::io::Read;
            let mut buf = vec![0u8; n];
            let got = f.read(&mut buf).unwrap_or(0);
            m.feed(0, &buf[..got]);
        } else {
            feed_headers_incrementally_pub(&mut f, size, &mut m);
        }
        let name = std::path::Path::new(p)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        println!(
            "== {} size={} physical={} ver={:?} volnum={:?} complete={} blocker={:?} entries={}",
            clip(&name, 24),
            size,
            physical,
            m.version,
            m.volume_number,
            m.complete,
            m.blocker,
            m.entries.len()
        );
        for e in &m.entries {
            println!(
                "   entry name={:?} unp={} dl={} off={} method={:?} enc={} dir={} szunk={} sb={} sa={} crc={:?} hash={}",
                clip(&e.name, 40),
                e.unpacked_size,
                e.data_len,
                e.data_off,
                e.method,
                e.encrypted,
                e.is_dir,
                e.size_unknown,
                e.split_before,
                e.split_after,
                e.file_crc,
                e.hash.is_some()
            );
            // Which key schedule the entry needs, and whether anything
            // could vouch for the password before decrypting: RAR4 never
            // can, so those sets always assemble ciphertext and take the
            // verdict from the CRC at finish.
            match &e.crypt {
                Some(EntryCrypt::Rar5(c)) => println!(
                    "     crypt=rar5 aes256 lg2={} check={} tweaked={}",
                    c.lg2_count,
                    c.check.is_some(),
                    c.tweaked_checksum
                ),
                Some(EntryCrypt::Rar4(c)) => println!(
                    "     crypt=rar4 aes128 salt={} check=none (verdict at finish)",
                    c.salt.is_some()
                ),
                None if e.encrypted => {
                    println!("     crypt=UNSUPPORTED (pre-3.0 cipher) - unrar fallback")
                }
                None => {}
            }
        }
        mappers.push(m);
    }
    let refs: Vec<&VolumeMapper> = mappers.iter().collect();
    match ArchiveMap::resolve_arithmetic(&refs) {
        ArithGate::Place { bases, closed } => {
            println!("GATE: Place closed={closed} bases={bases:?}")
        }
        ArithGate::Shape => println!("GATE: Shape"),
        ArithGate::Numbers => println!("GATE: Numbers"),
    }
}
