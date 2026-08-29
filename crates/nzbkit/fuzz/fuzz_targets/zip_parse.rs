#![no_main]
//! Fuzz the zip container parser on arbitrary bytes. A posted zip is
//! untrusted input that drives file creation, so both halves are
//! exercised: reading the central directory, and decoding every entry it
//! claims (which is where sizes, offsets and the deflate stream itself
//! come from the attacker).
//!
//! The reader works over a real file because it preads by offset, so the
//! target writes the input to a temp path per run.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cheap reject: without an end-of-central-directory signature the
    // parser bails immediately, and those inputs teach the fuzzer
    // nothing about the code that matters.
    if data.len() < 22 {
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbkit-fuzz-zip-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("f.zip");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    if let Ok(a) = nzbkit::zip::Archive::open(std::slice::from_ref(&path)) {
        for e in a.entries() {
            // Bound the sink: a valid header may legitimately claim a
            // huge entry, and the fuzzer should not be measuring RAM.
            let mut sink = CappedSink { left: 1 << 20 };
            let _ = a.read_entry_to(e, &mut sink);
            // Phase 3: drive the decrypt paths (ZipCrypto header check,
            // AE framing/PBKDF2/HMAC) over hostile input too. A fixed
            // password is fine - the attacker controls the archive, not
            // the password.
            let mut sink = CappedSink { left: 1 << 20 };
            let _ = a.read_entry_to_with(e, &mut sink, Some("pw"));
        }
    }
    let _ = std::fs::remove_file(&path);
});

struct CappedSink {
    left: usize,
}

impl std::io::Write for CappedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Err(std::io::Error::other("cap"));
        }
        let n = buf.len().min(self.left);
        self.left -= n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
