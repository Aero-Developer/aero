// SPDX-License-Identifier: BSD-3-Clause
//! Sign a release manifest with the Aero release key, without GnuPG installed.
//!
//! `gpg --detach-sign` is the normal way to do this and `RELEASING.md` documents it. This exists for
//! release machines that do not have GnuPG on them: it does the same job with rpgp, which the core
//! already carries as a dev-dependency for testing the verifier.
//!
//! An example rather than a binary on purpose. `cargo` gives examples the dev-dependencies, so this
//! compiles against rpgp while `aero.exe` and `aero_core.dll` cannot: nothing that ships is capable
//! of touching a secret key, and nothing that ships grows a signing code path that could be reached
//! by mistake.
//!
//! The signature is verified with Aero's own verifier before it is written, so this cannot produce a
//! `.asc` that the wallet would then refuse.
//!
//! ```powershell
//! cargo run --example sign-release -- <secret-key.asc> dist/aero-update.json dist/aero-update.json.asc
//! ```
//!
//! If the key is passphrase-protected, set AERO_KEY_PASSPHRASE.

use pgp::composed::{Deserializable, SignedSecretKey, StandaloneSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::PublicKeyTrait;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, key_path, doc_path, out_path] = args.as_slice() else {
        eprintln!(
            "usage: cargo run --example sign-release -- <secret-key.asc> <file> <file.asc>"
        );
        std::process::exit(2);
    };

    let armored = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| fail(&format!("cannot read {key_path}: {e}")));
    let (secret, _) = SignedSecretKey::from_string(&armored)
        .unwrap_or_else(|e| fail(&format!("{key_path} is not an OpenPGP secret key: {e}")));

    // Refuse early if this is not the key Aero trusts. Signing with the wrong key produces a file
    // that looks perfectly valid and is rejected by every copy of Aero in the world.
    let fingerprint = hex::encode_upper(secret.fingerprint().as_bytes());
    let want = hex::encode_upper(aero_core::pgp::RELEASE_FINGERPRINT);
    if fingerprint != want {
        fail(&format!(
            "that is key {fingerprint}, but Aero only accepts updates signed by {want}"
        ));
    }

    let document =
        std::fs::read(doc_path).unwrap_or_else(|e| fail(&format!("cannot read {doc_path}: {e}")));

    let passphrase = std::env::var("AERO_KEY_PASSPHRASE").unwrap_or_default();
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::SHA2_256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(chrono::Utc::now())),
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret.fingerprint())),
    ];
    config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::Issuer(secret.primary_key.key_id()))];

    let signature = config
        .sign(&secret.primary_key, || passphrase.clone(), &document[..])
        .unwrap_or_else(|e| {
            fail(&format!(
                "could not sign with that key: {e}\n\
                 (if the key has a passphrase, set AERO_KEY_PASSPHRASE and try again)"
            ))
        });
    let asc = StandaloneSignature::new(signature)
        .to_armored_string(Default::default())
        .unwrap_or_else(|e| fail(&format!("could not armor the signature: {e}")));

    // The check that matters: read it back with the code the wallet runs, against the key the wallet
    // pins. A signature this refuses must never reach a release page.
    match aero_core::pgp::verify_detached(&document, &asc) {
        Ok(when) => println!("signature verifies against the pinned Aero release key (at {when})"),
        Err(e) => fail(&format!("Aero would refuse the signature just produced: {e}")),
    }

    std::fs::write(out_path, asc.as_bytes())
        .unwrap_or_else(|e| fail(&format!("cannot write {out_path}: {e}")));
    println!("wrote {out_path}");
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}
