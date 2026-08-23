//! Update-manifest signing tool. The daemon verifies `latest.json` against an
//! ed25519 public key baked into the binary (see UPDATE_PUBKEY_HEX in
//! serve/update.rs); this tool holds the *private* half, which never lives in
//! the repo or on a build server - it stays offline with the release manager.
//!
//!   keygen [out.hex]                -> fresh keypair. With a path, the PRIVATE
//!                                      key is written there (0600) and only the
//!                                      public key is printed, so the secret
//!                                      never lands in terminal scrollback.
//!   pubkey  <priv.hex>              -> prints the public key for a private key
//!   sign    <priv.hex> <latest.json> -> writes <latest.json>.sig (detached, hex)
//!
//! The signature covers the exact bytes of latest.json, so there is no JSON
//! canonicalization to get wrong: sign the file, ship the .sig beside it.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let rc = match cmd {
        "keygen" => keygen(args.get(2)),
        "pubkey" => pubkey(args.get(2)),
        "sign" => sign(args.get(2), args.get(3)),
        _ => {
            eprintln!(
                "usage:\n  update_sign keygen\n  update_sign pubkey <priv.hex>\n  update_sign sign <priv.hex> <latest.json>"
            );
            2
        }
    };
    std::process::exit(rc);
}

fn load_priv(path: Option<&String>) -> Result<SigningKey, String> {
    let path = path.ok_or("missing private-key path")?;
    let hexstr = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let raw = hex::decode(hexstr.trim()).map_err(|e| format!("private key not hex: {e}"))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

fn keygen(out: Option<&String>) -> i32 {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("getrandom failed: {e}");
        return 1;
    }
    let sk = SigningKey::from_bytes(&seed);
    let vk: VerifyingKey = sk.verifying_key();
    let priv_hex = hex::encode(sk.to_bytes());
    let pub_hex = hex::encode(vk.to_bytes());
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &priv_hex) {
                eprintln!("write {path}: {e}");
                return 1;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            println!(
                "private key written to {path} (0600) - keep it offline, back it up, never commit it"
            );
            println!("public  (embed in serve.rs UPDATE_PUBKEY_HEX): {pub_hex}");
        }
        None => {
            println!("private (KEEP OFFLINE): {priv_hex}");
            println!("public  (embed in serve.rs UPDATE_PUBKEY_HEX): {pub_hex}");
        }
    }
    0
}

fn pubkey(path: Option<&String>) -> i32 {
    match load_priv(path) {
        Ok(sk) => {
            println!("{}", hex::encode(sk.verifying_key().to_bytes()));
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn sign(priv_path: Option<&String>, manifest: Option<&String>) -> i32 {
    let sk = match load_priv(priv_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let manifest = match manifest {
        Some(m) => m,
        None => {
            eprintln!("missing manifest path");
            return 2;
        }
    };
    let bytes = match std::fs::read(manifest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {manifest}: {e}");
            return 1;
        }
    };
    let sig = sk.sign(&bytes);
    let out = format!("{manifest}.sig");
    if let Err(e) = std::fs::write(&out, hex::encode(sig.to_bytes())) {
        eprintln!("write {out}: {e}");
        return 1;
    }
    // Self-check: the freshly written signature must verify under our own
    // public key before we claim success.
    if sk.verifying_key().verify_strict(&bytes, &sig).is_err() {
        eprintln!("internal error: signature failed self-verification");
        return 1;
    }
    println!("wrote {out}");
    0
}
