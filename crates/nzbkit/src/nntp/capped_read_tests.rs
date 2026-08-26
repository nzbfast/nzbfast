//! The multiline read cap, at unit speed. A child module (the
//! `unit_tests` pattern in nntp.rs) so nntp.rs stays inside its
//! size-gate entry while `super::` keeps the internals reachable.

use super::{NntpError, read_multiline_paced_max};

/// The cap must not depend on how the response was chunked.
///
/// `preflight::tests::a_capped_body_stops_reading_at_the_caller_s_allowance`
/// drives this through a socket, where the split is the loopback's
/// choice: it caught the missing check on Windows, which delivered
/// the body in one piece, and passed on Linux and macOS, which did
/// not. A `Cursor` hands the whole slice back from a single
/// `fill_buf`, so this reaches the terminator-inside-the-chunk arm
/// on EVERY platform and fails deterministically without the check.
#[tokio::test]
async fn the_cap_binds_when_the_terminator_arrives_in_the_same_chunk() {
    let mut wire = Vec::new();
    wire.extend_from_slice(&vec![b'x'; 200_000]);
    wire.extend_from_slice(b"\r\n.\r\n");

    let mut out = Vec::new();
    let err = read_multiline_paced_max(
        &mut std::io::Cursor::new(&wire[..]),
        &mut out,
        std::time::Duration::from_secs(5),
        8_192,
        None,
    )
    .await
    .expect_err("a 200 KB body under an 8 KiB cap must be refused");
    assert!(
        matches!(err, NntpError::TooLarge(8_192)),
        "expected TooLarge(8192), got {err:?}"
    );

    // The boundary, exactly. What the caller receives is the payload
    // PLUS the terminating CRLF of its last line - 200_002 bytes -
    // because the copy runs to the dot. One byte under that is a
    // refusal; the figure itself is returned whole.
    const BODY: usize = 200_002;
    let mut out = Vec::new();
    let err = read_multiline_paced_max(
        &mut std::io::Cursor::new(&wire[..]),
        &mut out,
        std::time::Duration::from_secs(5),
        BODY - 1,
        None,
    )
    .await
    .expect_err("one byte under the body must be refused");
    assert!(
        matches!(err, NntpError::TooLarge(n) if n == BODY - 1),
        "{err:?}"
    );

    let mut out = Vec::new();
    read_multiline_paced_max(
        &mut std::io::Cursor::new(&wire[..]),
        &mut out,
        std::time::Duration::from_secs(5),
        BODY,
        None,
    )
    .await
    .expect("a body exactly at the allowance must be returned");
    assert_eq!(out.len(), BODY);
}
