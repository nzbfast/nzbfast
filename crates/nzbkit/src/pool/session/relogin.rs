//! TODO 358 items 2 and 12: a mid-session `480 authentication required`
//! or `412 no newsgroup selected` is answered on the SAME socket.
//!
//! Until this module, both reached `session_loop` as an
//! [`crate::nntp::NntpError::Unexpected`] to a BODY and took the
//! protocol-death arm: quit, requeue the pipeline, redial. That is the
//! right answer to a status a BODY cannot have, and the wrong one to
//! these two, because neither is about the article or about the
//! socket's alignment. A 480 says the login this socket made at connect
//! has lapsed (providers with a login timeout do it to long-lived
//! sessions), and a 412 says this frontend wants a group selected
//! before it will look a message-id up. Each is fixed by one command on
//! the connection we already hold, which is what Weaver does since
//! 0.16.11 for the 480 (`research/PLAN-WEAVER-PARITY-2026-11-08.md`).
//! The redial cost a dial, a TLS handshake and a login per lapse, and on
//! a session that had not yet completed a response it also CHARGED the
//! front article (`requeue_or_fail`'s zero-response rule), so a server
//! that 480s the first BODY after every connect walked innocent
//! articles to Failed.
//!
//! The recovery, in order:
//!
//! 1. Gate. A 480 is answered only when the server has credentials and
//!    the session has completed a useful response since its previous
//!    re-login (`SessionState::relogin_at`), so a server that 480s the
//!    re-asked article straight back cannot loop a session through
//!    logins. A 412 is answered only when the pool knows the job's
//!    group (`PoolConfig::group`) and has not already sent it on this
//!    session (`SessionState::group_sent`).
//! 2. Drain. Every command already on the wire behind the refused one
//!    still owes a response, and a login read off a socket with BODY
//!    answers queued on it would be misattributed exactly as a dropped
//!    pipelined response is. So each outstanding response is read and
//!    DISCARDED - a body that arrives anyway is read to its terminator
//!    and thrown away, a refusal is thrown away too - along with each
//!    fence answer (§129 3g) riding behind a fenced item. Every article
//!    is re-asked below, so nothing read here is evidence of anything.
//! 3. The one command: `AUTHINFO USER/PASS` or `GROUP <name>`.
//! 4. Re-send the whole pipeline, in its original order, unflushed -
//!    `session_loop` flushes before its next read, exactly as it does
//!    after a top-up.
//!
//! The in-flight deque is never touched, which is what makes the re-ask
//! UNCHARGED by construction: no `Work` leaves it, so no `attempts`
//! bump, no `tried_fail` bit, no wire-cap release and re-charge, and no
//! deregistration. Any failure at any step returns false and the caller
//! takes the old protocol-death arm with the ORIGINAL error, so the
//! fallback is byte-for-byte today's behaviour (the pins are in
//! `pool::relogin_rigs`).

use super::*;
use crate::nntp::SessionRefusal;

/// The one command a [`SessionRefusal`] is answered with, resolved at
/// the gate so the steps after it cannot disagree with it.
enum Cmd<'a> {
    Login(&'a str, &'a str),
    Group(&'a str),
}

/// Answer a [`SessionRefusal`] read for the front of `sess.inflight`.
/// True: the socket is recovered and the pipeline re-sent, keep reading.
/// False: not on offer, or a step failed - the caller ends the session
/// as it would have before this existed.
pub(super) async fn recover(
    conn: &mut Connection,
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    sess: &mut SessionState,
    kind: SessionRefusal,
) -> bool {
    let cmd = match kind {
        SessionRefusal::AuthRequired => {
            let (Some(user), Some(pass)) = (&server.username, &server.password) else {
                return false;
            };
            if sess.relogin_at == Some(sess.responses) {
                return false;
            }
            // Stamped before the attempt: a failed one ends the session
            // anyway, and a stamp that only landed on success would let a
            // future caller retry a refused login on the same evidence.
            sess.relogin_at = Some(sess.responses);
            Cmd::Login(user, pass)
        }
        SessionRefusal::NoGroup => {
            let Some(group) = cfg.group.as_deref() else {
                return false;
            };
            if sess.group_sent {
                return false;
            }
            sess.group_sent = true;
            Cmd::Group(group)
        }
    };
    // One bound over the whole recovery: the drain is reading answers the
    // server already owes (a refusal each, in the expected case), so the
    // flat read timeout is generous for it and still finite on a server
    // that goes mute mid-drain.
    let steps = async {
        drain(conn, &sess.inflight).await?;
        match cmd {
            Cmd::Login(user, pass) => conn.authenticate(user, pass).await?,
            Cmd::Group(group) => {
                conn.group(group).await?;
            }
        }
        resend(conn, &sess.inflight).await
    };
    match tokio::time::timeout(cfg.read_timeout, steps).await {
        Ok(Ok(())) => {
            info!(
                target: "pool",
                "{}: server {} {}; re-asked {} article(s) on the same connection",
                server.host,
                ctx.idx,
                match kind {
                    SessionRefusal::AuthRequired => "asked for a fresh login (480), logged in again",
                    SessionRefusal::NoGroup => "wanted a newsgroup selected (412), sent GROUP",
                },
                sess.inflight.len()
            );
            true
        }
        Ok(Err(e)) => {
            warn!(
                target: "pool",
                "{}: server {}: answering a {} on the same connection failed ({e}); reconnecting",
                server.host,
                ctx.idx,
                match kind {
                    SessionRefusal::AuthRequired => "480",
                    SessionRefusal::NoGroup => "412",
                },
            );
            false
        }
        Err(_) => false,
    }
}

/// Read and discard every response still owed behind the refused one.
/// The refused command's own status line is already consumed; its fence
/// answer, if it carried one, is not, because `read_one` reads a fence
/// only after a well-formed answer.
async fn drain(
    conn: &mut Connection,
    inflight: &VecDeque<Work>,
) -> Result<(), crate::nntp::NntpError> {
    let mut scratch = Vec::new();
    for (i, w) in inflight.iter().enumerate() {
        if i > 0 {
            let st = conn.read_status().await?;
            // The three multiline answers an article command can carry.
            // Anything else (a refusal, a 223, another 480) is one line.
            if matches!(st.code, 220..=222) {
                scratch.clear();
                conn.read_multiline_into(&mut scratch).await?;
            }
        }
        if w.fenced {
            // A fence answer is one line whatever it says (111, a 480,
            // a 500 from a DATE-less frontend). A multiline code here is
            // a stream that is off by one, and nothing after it can be
            // attributed - give up and let the session die.
            let st = conn.read_status().await?;
            if matches!(st.code, 220..=222) {
                return Err(crate::nntp::NntpError::Unexpected {
                    cmd: "DATE".into(),
                    line: st.into_line(),
                });
            }
        }
    }
    Ok(())
}

/// Put the whole pipeline back on the wire in its original order, with
/// the same command (BODY or STAT) and the same fence each item went
/// out with, so every reader downstream sees exactly the conversation
/// it dispatched.
async fn resend(
    conn: &mut Connection,
    inflight: &VecDeque<Work>,
) -> Result<(), crate::nntp::NntpError> {
    for w in inflight {
        if w.probe {
            conn.send_stat(&w.id).await?;
        } else {
            conn.send_body(&w.id).await?;
        }
        if w.fenced {
            conn.send_fence().await?;
        }
    }
    Ok(())
}
