//! Read-only sweep, 9 Nov 2026: [`join_decode_consumers`] names a decode
//! thread that panicked. The join was `let _ = c.join()`, so the job log
//! never said a thread had died and the articles it held went unresolved
//! with no reason given anywhere a user could see.

use super::*;

#[test]
fn a_panicked_decode_thread_is_named_and_a_clean_one_is_not() {
    let clean = std::thread::Builder::new()
        .name("decode-0".into())
        .spawn(|| {})
        .unwrap();
    let dead = std::thread::Builder::new()
        .name("decode-1".into())
        .spawn(|| panic!("yEnc line overran its buffer"))
        .unwrap();
    let owned = std::thread::Builder::new()
        .name("decode-2".into())
        .spawn(|| std::panic::panic_any(format!("slot {} out of range", 7)))
        .unwrap();
    let got = join_decode_consumers(vec![clean, dead, owned]);
    assert_eq!(
        got,
        vec![
            "decode-1 panicked: yEnc line overran its buffer".to_string(),
            "decode-2 panicked: slot 7 out of range".to_string(),
        ]
    );
}
