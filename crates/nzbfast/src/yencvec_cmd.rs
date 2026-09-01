//! `nzbfast yenc-vectors` - write a deterministic test corpus for the
//! Tensai75 yEnc encryption standards (yenc-encryption-standards, both
//! RFC-DRAFTs at v0.3), which ship without test vectors or a reference
//! implementation. The corpus is everything a second implementer needs
//! to validate against ours: the plaintext files, every article as it
//! would cross the wire, the NZBs with the draft's required `[n/total]`
//! subjects and password meta tag, and a manifest carrying the full
//! derivation chain (keys, nonces, tweaks, tags) under the declared
//! conventions in `nzbkit::yencrypt`'s header.
//!
//! Everything is DETERMINISTIC on purpose - fixed payloads, fixed
//! session salts, fixed message-ids - so two runs anywhere produce
//! byte-identical corpora, which is what makes the output citable as
//! vectors rather than merely as an example. No network is touched.

use anyhow::Context;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub struct VecArgs {
    pub out: PathBuf,
    pub password: String,
    pub article_size: usize,
}

/// Corpus-wide fixed session salts. The body salt is the pinned-vector
/// salt from `nzbkit::yencrypt`'s tests; the control salt is distinct
/// (the draft never says the two layers share one) and alphabet-clean.
const BODY_SALT: [u8; 16] = *b"0123456789abcdef";
const CONTROL_SALT: [u8; 16] = *b"ctrl-salt-16byte";

/// xorshift32 keystream: deterministic payload bytes with full byte
/// coverage, so yEnc escaping (NUL, CR, LF, '=') is exercised.
fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut s = seed.max(1);
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 24) as u8
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(b))
}

/// One variant directory: `articles/<message-id>.body` (the exact NNTP
/// BODY bytes), `post.nzb`, and its slice of the manifest.
struct Variant {
    name: &'static str,
    files: Vec<(String, Vec<(String, u64, u32)>)>,
    articles: std::collections::HashMap<String, Vec<u8>>,
    manifest: String,
}

impl Variant {
    fn write(&self, root: &Path, password: &str) -> anyhow::Result<()> {
        let dir = root.join(self.name);
        let arts = dir.join("articles");
        std::fs::create_dir_all(&arts).with_context(|| format!("mkdir {}", arts.display()))?;
        for (id, body) in &self.articles {
            let clean = id.trim_matches(['<', '>']);
            std::fs::write(arts.join(format!("{clean}.body")), body)?;
        }
        std::fs::write(dir.join("post.nzb"), self.nzb(password))?;
        std::fs::write(dir.join("MANIFEST.txt"), &self.manifest)?;
        Ok(())
    }

    /// The draft's NZB shape: `[n/total]` on every subject (Section 8
    /// of both standards) and the password as the standard meta tag.
    fn nzb(&self, password: &str) -> String {
        let total = self.files.len();
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        let _ = writeln!(
            xml,
            "  <head><meta type=\"password\">{password}</meta></head>"
        );
        for (i, (name, segs)) in self.files.iter().enumerate() {
            let _ = writeln!(
                xml,
                "  <file poster=\"vectors@nzbfast.invalid\" date=\"0\" subject=\"[{}/{total}] &quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>alt.binaries.test</group></groups>\n    <segments>",
                i + 1,
                segs.len()
            );
            for (id, bytes, num) in segs {
                let _ = writeln!(
                    xml,
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>"
                );
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        xml
    }
}

/// The two corpus files, small enough to eyeball and big enough for
/// multiple articles each (so the continuous segmentIndex is visible).
fn corpus_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("Alpha.bin", payload(20_000, 0xA1)),
        ("Beta.bin", payload(9_500, 0xB2)),
    ]
}

pub fn run(args: VecArgs) -> anyhow::Result<()> {
    let key = nzbkit::yencrypt::derive_key(&args.password, &BODY_SALT);
    let ctrl_master = nzbkit::yencrypt::derive_key(&args.password, &CONTROL_SALT);
    let cc = nzbkit::yencrypt::ControlCrypt::new(&ctrl_master);
    let files = corpus_files();
    std::fs::create_dir_all(&args.out).with_context(|| format!("mkdir {}", args.out.display()))?;
    let plain_dir = args.out.join("plain");
    std::fs::create_dir_all(&plain_dir)?;
    for (name, data) in &files {
        std::fs::write(plain_dir.join(name), data)?;
    }

    let mut variants = Vec::new();
    for mode in ["body", "control", "combined"] {
        let mut v = Variant {
            name: mode,
            files: Vec::new(),
            articles: std::collections::HashMap::new(),
            manifest: String::new(),
        };
        let m = &mut v.manifest;
        let _ = writeln!(m, "yEnc encryption vectors - {mode} standard");
        let _ = writeln!(m, "password: {:?}", args.password);
        let _ = writeln!(
            m,
            "declared conventions: see nzbkit::yencrypt module header\n\
             (u32 BE indices, Argon2id v1.3 m=65536KiB t=1 p=4,\n\
             physical lineIndex, ascending 253-alphabet bijection)"
        );
        if mode != "control" {
            let _ = writeln!(m, "body salt: {}", hex(&BODY_SALT));
            let _ = writeln!(m, "body key (Argon2id): {}", hex(&key));
        }
        if mode != "body" {
            let _ = writeln!(m, "control salt: {}", hex(&CONTROL_SALT));
            let _ = writeln!(m, "control master (Argon2id): {}", hex(&ctrl_master));
        }
        let mut base = 1u32;
        for (name, data) in &files {
            let tag_prefix = format!("{mode}-{}", name.to_lowercase().replace('.', "-"));
            let segs = if mode == "control" {
                nzbkit::mock::make_file_articles(
                    name,
                    data,
                    args.article_size,
                    &tag_prefix,
                    &mut v.articles,
                )
            } else {
                nzbkit::mock::make_file_articles_encrypted(
                    name,
                    data,
                    args.article_size,
                    &tag_prefix,
                    &key,
                    &BODY_SALT,
                    base,
                    &mut v.articles,
                )
            };
            for (id, _, num) in &segs {
                let seg = base + num - 1;
                let bkey = format!("<{id}>");
                if mode != "body" {
                    let art = v.articles.get_mut(&bkey).expect("article just added");
                    *art = nzbkit::yencrypt::control_encrypt_block(&cc, &CONTROL_SALT, seg, art)
                        .expect("fixture lines are alphabet-clean");
                }
                let art = &v.articles[&bkey];
                let _ = writeln!(m, "file: {name} segment: {num} message-id: <{id}>");
                let _ = writeln!(m, "  segmentIndex: {seg}");
                if mode != "control" {
                    let chunk_at = (*num as usize - 1) * args.article_size;
                    let chunk_end = (chunk_at + args.article_size).min(data.len());
                    let mut ct = data[chunk_at..chunk_end].to_vec();
                    let tag = nzbkit::yencrypt::encrypt_segment(&key, seg, &mut ct);
                    let _ = writeln!(
                        m,
                        "  nonce: {}",
                        hex(&nzbkit::yencrypt::nonce_for(&key, seg))
                    );
                    let _ = writeln!(m, "  poly1305 tag: {}", hex(&tag));
                    let _ = writeln!(m, "  ciphertext sha256: {}", sha256_hex(&ct));
                }
                let _ = writeln!(m, "  article sha256: {}", sha256_hex(art));
            }
            base += segs.len() as u32;
            v.files.push((name.to_string(), segs));
        }
        variants.push(v);
    }
    for v in &variants {
        v.write(&args.out, &args.password)?;
    }

    // Top-level derivation-chain vectors: the same values the module's
    // pinned tests assert, printed so a consumer validates the chain
    // without reading Rust.
    let mut top = String::from("yEnc encryption derivation vectors (Tensai75 draft v0.3)\n");
    let _ = writeln!(
        top,
        "\nBody standard - password \"test123\", salt ASCII \"0123456789abcdef\",\nsegmentIndex 1, plaintext \"Hello World.txt!!!\":"
    );
    let vk = nzbkit::yencrypt::derive_key("test123", b"0123456789abcdef");
    let _ = writeln!(top, "  key:   {}", hex(&vk));
    let _ = writeln!(
        top,
        "  nonce: {}",
        hex(&nzbkit::yencrypt::nonce_for(&vk, 1))
    );
    let mut buf = b"Hello World.txt!!!".to_vec();
    let vtag = nzbkit::yencrypt::encrypt_segment(&vk, 1, &mut buf);
    let _ = writeln!(top, "  ct:    {}", hex(&buf));
    let _ = writeln!(top, "  tag:   {}", hex(&vtag));
    let _ = writeln!(
        top,
        "\nControl-lines standard - same password and salt, segmentIndex 1,\nline 1 content \"=ybegin line=9 size=18 name=file.bin\":"
    );
    let vcc = nzbkit::yencrypt::ControlCrypt::new(&vk);
    let vct = vcc
        .encrypt_line(1, 1, b"=ybegin line=9 size=18 name=file.bin")
        .expect("vector line is alphabet-clean");
    let _ = writeln!(top, "  ff1 ciphertext: {}", hex(&vct));
    std::fs::write(args.out.join("VECTORS.txt"), top)?;

    println!(
        "wrote yEnc encryption corpus to {} (plain, body, control, combined; password {:?})",
        args.out.display(),
        args.password
    );
    Ok(())
}
