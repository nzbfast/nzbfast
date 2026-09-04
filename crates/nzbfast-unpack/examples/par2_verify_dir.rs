//! Whole-directory PAR2 verification driver: one wall-clock number.
//!
//! The A/B leg the AWS-LC MD5 work was measured on. It opts out of power
//! throttling first, so a laptop leg is not measuring the governor.

use std::time::Instant;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: par2_verify_dir <dir>");
    nzbkit::mem::opt_out_of_power_throttling();
    let started = Instant::now();
    let verdict = nzbfast_unpack::unpack::verify_dir(std::path::Path::new(&dir));
    println!("total {:.3?} verdict: {verdict:?}", started.elapsed());
    assert_eq!(verdict.unwrap(), nzbfast_unpack::unpack::DirVerify::Clean);
}
