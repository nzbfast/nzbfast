//! RAR5 extraction CPU benchmark with parsing outside the timer.
//! Usage: bench_rar5_paths DIR [ROUNDS] [auto|serial|ring] [PASSWORD]
//! Each directory is one archive's volume set. Normal extraction verifies
//! archive checksums; the counting sink also checks the emitted byte count.
use rars::{ArchiveReadOptions, Rar50ExecutionPolicy, ReadSession};
use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

struct Count(Arc<AtomicU64>);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let dir = args
        .get(1)
        .expect("DIR [ROUNDS] [auto|serial|ring] [PASSWORD]");
    let rounds = args
        .get(2)
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(10);
    let mode = args.get(3).map(String::as_str).unwrap_or("auto");
    let mut options = args
        .get(4)
        .map(|p| ArchiveReadOptions::with_password(p.as_bytes()))
        .unwrap_or_default();
    match mode {
        "auto" => {}
        "ring" => options = options.with_rar50_buffered_decode_limit(0),
        "serial" => {
            let mut policy = Rar50ExecutionPolicy::from_working_memory(512 << 20);
            policy.max_workers = 1;
            policy.max_tape_workers = 1;
            options = options.with_rar50_execution_policy(policy);
        }
        _ => panic!("unknown mode: {mode}"),
    }
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| p.extension().is_some_and(|s| s == "rar"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no RAR volumes");
    let mut session = ReadSession::new(options.clone());
    let archives: Vec<_> = paths
        .iter()
        .map(|p| session.read_path(p).unwrap())
        .collect();
    let mut expected = None;
    for round in 0..=rounds {
        let count = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        rars::extract_volumes_to_with_options(&archives, options.clone(), |_| {
            Ok(Box::new(Count(count.clone())) as Box<dyn Write>)
        })
        .unwrap();
        let seconds = start.elapsed().as_secs_f64();
        let bytes = count.load(Ordering::Relaxed);
        assert_eq!(*expected.get_or_insert(bytes), bytes);
        // Round zero warms code and file pages without entering the result.
        if round != 0 {
            println!("round={round} mode={mode} bytes={bytes} seconds={seconds:.9}");
        }
    }
}
