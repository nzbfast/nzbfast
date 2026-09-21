//! Unit tests for the session store and the password hashing behind the
//! login form (TODO 19). The end-to-end half - the routes, the cookie on
//! the wire, key-only clients unaffected - is in the daemon suite.

use super::*;

#[test]
fn a_password_round_trips_and_a_wrong_one_does_not() {
    let h = hash_password("correct horse").expect("hash");
    assert!(
        h.starts_with("$argon2id$"),
        "not a PHC argon2id string: {h}"
    );
    assert!(verify_password("correct horse", &h));
    assert!(!verify_password("correct horsf", &h));
    assert!(!verify_password("", &h));
}

/// The salt is per-password, so two hashes of the same password differ -
/// which is what stops a stolen settings.json telling an attacker that
/// two installs share a password.
#[test]
fn the_same_password_hashes_differently_every_time() {
    let a = hash_password("same").expect("hash");
    let b = hash_password("same").expect("hash");
    assert_ne!(a, b);
    assert!(verify_password("same", &a) && verify_password("same", &b));
}

/// settings.json is a file a user may hand-edit, so a value that is not a
/// PHC string at all must read as "does not match" rather than panicking
/// on a worker thread.
#[test]
fn a_corrupt_stored_hash_refuses_instead_of_erroring() {
    for junk in ["", "hunter2", "$argon2id$", "$notanalgo$v=19$m=1$x$y"] {
        assert!(!verify_password("hunter2", junk), "accepted junk {junk:?}");
    }
}

#[test]
fn a_session_needs_its_csrf_token() {
    let s = Sessions::default();
    let (id, csrf) = s.create().expect("mint");
    assert!(matches!(s.check(Some(&id), Some(&csrf)), SessionCheck::Ok));
    assert!(matches!(
        s.check(Some(&id), Some("wrong")),
        SessionCheck::NoCsrf
    ));
    assert!(matches!(s.check(Some(&id), None), SessionCheck::NoCsrf));
    // An unknown id is None (fall back to the key), never NoCsrf: a
    // caller who sent no cookie must not be told a session exists.
    assert!(matches!(
        s.check(Some("nope"), Some(&csrf)),
        SessionCheck::None
    ));
    assert!(matches!(s.check(None, None), SessionCheck::None));
}

#[test]
fn logout_drops_one_and_a_credential_change_drops_all() {
    let s = Sessions::default();
    let (a, ca) = s.create().expect("mint");
    let (b, cb) = s.create().expect("mint");
    s.drop_one(Some(&a));
    assert!(matches!(s.check(Some(&a), Some(&ca)), SessionCheck::None));
    assert!(matches!(s.check(Some(&b), Some(&cb)), SessionCheck::Ok));
    s.drop_all();
    assert!(matches!(s.check(Some(&b), Some(&cb)), SessionCheck::None));
    assert_eq!(s.live_count(), 0);
}

/// The store is bounded, and the eviction takes the OLDEST deadline - so
/// the browser that just signed in is never the one thrown out.
#[test]
fn the_store_is_bounded_and_evicts_the_oldest() {
    let s = Sessions::default();
    let mut ids = Vec::new();
    for _ in 0..SESSION_MAX + 5 {
        ids.push(s.create().expect("mint"));
        // Every session gets the same TTL, so without a gap between
        // mints the deadlines tie and "oldest" is not defined. One
        // millisecond is enough for `Instant` on every platform here.
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(s.live_count(), SESSION_MAX);
    let (first, fc) = &ids[0];
    assert!(matches!(s.check(Some(first), Some(fc)), SessionCheck::None));
    let (last, lc) = ids.last().expect("one");
    assert!(matches!(s.check(Some(last), Some(lc)), SessionCheck::Ok));
}

/// The read-only media doors take `is_live`, which asks nothing about
/// CSRF - see its doc comment for why a `<video src=…>` cannot carry a
/// header and why that is safe for a read.
#[test]
fn is_live_ignores_csrf_and_unknown_ids() {
    let s = Sessions::default();
    let (id, _) = s.create().expect("mint");
    assert!(s.is_live(Some(&id)));
    assert!(!s.is_live(Some("nope")));
    assert!(!s.is_live(Some("")));
    assert!(!s.is_live(None));
}

/// The cookie name carries the port, so two daemons on one host do not
/// log each other out. Cookies ignore the port by themselves.
#[test]
fn the_cookie_names_carry_the_port() {
    assert_eq!(session_cookie(6789), "nzbfast_session_6789");
    assert_eq!(csrf_cookie(6789), "nzbfast_csrf_6789");
    assert_ne!(session_cookie(6789), session_cookie(7000));
}

#[test]
fn the_login_cookies_say_what_they_must() {
    let [sess, csrf] = login_cookies(6789, "ID", "TOK", false);
    assert!(sess.starts_with("nzbfast_session_6789=ID;"));
    assert!(sess.contains("HttpOnly"), "{sess}");
    assert!(sess.contains("SameSite=Lax"), "{sess}");
    assert!(sess.contains("Path=/"), "{sess}");
    assert!(
        !sess.contains("Secure"),
        "plain http must not be Secure: {sess}"
    );
    // The companion is deliberately readable - the pages echo it back.
    assert!(!csrf.contains("HttpOnly"), "{csrf}");
    assert!(csrf.starts_with("nzbfast_csrf_6789=TOK;"));
    let [sess, _] = login_cookies(6789, "ID", "TOK", true);
    assert!(sess.contains("; Secure"), "{sess}");
    for c in logout_cookies(6789) {
        assert!(c.contains("Max-Age=0"), "{c}");
    }
}

/// The password floor, and the refusals chosen for a PASSWORD rather
/// than inherited from the API key.
///
/// The reasoning is measured in
/// `research/LOGIN-RATE-LIMIT-MEASURED-2026-09-20.md` and stated at
/// `WORST_PASSWORDS`: the `/login` ladder does not limit an attacker's
/// guess rate, so the credential is the defence, so the credentials that
/// fall to a spray in under a second are refused at the point they are
/// set.
#[test]
fn the_worst_passwords_are_refused_and_ordinary_ones_are_not() {
    // Length is still the first rule, and still in the words the
    // settings page and the daemon suite have always matched on.
    assert!(
        password_refusal("abc", "owner")
            .expect("too short")
            .contains("at least 8 characters")
    );
    // The list, case-insensitively.
    for pw in ["password", "PASSWORD", "12345678", "QwErTy123", "changeme"] {
        assert!(password_refusal(pw, "owner").is_some(), "{pw} was accepted");
    }
    // The structural rules, which generalise where a list cannot.
    assert!(password_refusal("aaaaaaaa", "owner").is_some());
    // Eight spaces is one character repeated too, and the rule catching
    // it is correct rather than over-eager: this expectation was written
    // the other way round first and the test refused it.
    assert!(password_refusal("        ", "owner").is_some());
    assert!(password_refusal("abcdefgh", "owner").is_some());
    assert!(password_refusal("87654321", "owner").is_some());
    // The username itself, which no list can hold - the value that makes
    // it weak belongs to this install.
    assert!(password_refusal("SomeOwner", "someowner").is_some());
    // ...and with no username configured yet that rule simply does not
    // fire, rather than refusing every password against "".
    assert!(password_refusal("correct horse battery", "").is_none());

    // What must still be ACCEPTED. A refusal a normal password trips is
    // worse than no refusal at all: it trains the owner to pick
    // something shorter that slips through.
    for pw in [
        "correct horse battery staple",
        "Tr0ub4dor&3",
        "hunter2hunter2",
        "passwordiche", // NOT on the list: the list is exact, not a substring match
        "abcdefgi",     // one character off a run
    ] {
        assert!(
            password_refusal(pw, "owner").is_none(),
            "{pw:?} was refused and should not have been"
        );
    }

    // And the one that matters for an upgrade: this judges a password
    // being SET, never one already stored. A stored Argon2 PHC string
    // is restored without going near the setter
    // (settings_restore.rs), so nobody is locked out of an install by
    // this rule landing.
    assert!(
        password_refusal("$argon2id$v=19$m=19456,t=2,p=1$abc$def", "owner").is_none(),
        "a stored hash must not be judged as a password"
    );
}

/// The concurrency cap releases its permits.
///
/// The interesting half of the cap - four at once and the fifth asked to
/// retry - needs concurrency and a real daemon, and lives in the daemon
/// suite (`daemon_weblogin`: `only_four_password_checks_run_at_once…`).
/// What belongs HERE is the failure that suite would be slow to notice
/// and that would be catastrophic in production: a permit that is taken
/// and never given back shrinks the cap by one every sign-in and ends
/// with a daemon that answers 503 to every login forever. Sequential
/// calls well past the cap are the cheapest possible proof that the
/// `Drop` runs.
#[test]
fn the_verify_cap_hands_its_permits_back() {
    let h = hash_password("correct horse").expect("hash");
    for i in 0..(VERIFY_PERMITS * 2 + 1) {
        match verify_password_capped("correct horse", &h) {
            VerifyOutcome::Checked(ok) => assert!(ok, "call {i} rejected the right password"),
            VerifyOutcome::Busy => {
                panic!("call {i} found no free permit with nothing else running - a permit leaked")
            }
        }
    }
    // ...and a wrong password is still wrong through the capped door.
    match verify_password_capped("correct horsf", &h) {
        VerifyOutcome::Checked(ok) => assert!(!ok, "the capped door accepted a wrong password"),
        VerifyOutcome::Busy => panic!("a permit leaked"),
    }
}
