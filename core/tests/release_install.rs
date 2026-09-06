// SPDX-License-Identifier: BSD-3-Clause
//! Installs a real release archive over a real installation layout.
//!
//! The unit tests in `update.rs` use small archives built for the occasion, which is the right way
//! to test the rules but says nothing about the artifact that actually ships: a sixty-megabyte zip
//! produced by `Compress-Archive`, containing nested plugin folders, a Tor build and a few hundred
//! entries. This test takes that file, as built by `ci/release.ps1`, and installs it over a folder
//! laid out the way a user's portable install is - wallets and all.
//!
//! It skips itself when there is no release zip to test, so a plain `cargo test` on a fresh checkout
//! stays green. Build one with:
//!
//! ```powershell
//! pwsh ci/release.ps1 -Version <version>
//! ```

use std::path::{Path, PathBuf};

/// The most recently built release archive in `dist/`, if there is one.
///
/// Chosen by modification time, not by name: `dist/` accumulates every release ever cut, and sorting
/// those names alphabetically puts 0.1.9 after 0.1.28 and an old unversioned zip after both.
fn release_archive() -> Option<PathBuf> {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist");
    std::fs::read_dir(dist)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("Aero-") && n.ends_with("-portable.zip"))
        })
        .filter_map(|p| {
            let when = std::fs::metadata(&p).ok()?.modified().ok()?;
            Some((when, p))
        })
        .max_by_key(|(when, _)| *when)
        .map(|(_, p)| p)
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_default()
}

#[test]
fn a_real_release_archive_installs_over_a_real_wallet_folder() {
    let Some(archive) = release_archive() else {
        eprintln!("no release zip in dist/ - skipping (run ci/release.ps1 to build one)");
        return;
    };
    eprintln!("installing {}", archive.display());

    let root = std::env::temp_dir().join(format!(
        "aero-release-install-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();

    // A portable install that has been used: an older Aero, and the user's data beside it. The
    // wallet contents here are invented; the point is that whatever bytes are in these files are
    // the bytes still in them afterwards.
    write(&root, "aero_gui.exe", "PREVIOUS VERSION");
    write(&root, "aero_core.dll", "PREVIOUS CORE");
    write(&root, "portable", "portable marker");
    write(&root, "wallets/wallet/wallet.keys", "ENCRYPTED KEYSTORE");
    write(&root, "wallets/wallet_5/wallet_5.keys", "ANOTHER KEYSTORE");
    write(&root, "config/Aero/Aero.ini", "[tor]\nexternal=false");
    write(&root, "thp-pairing.txt", "trezor credential");
    write(&root, "tor/data/state", "tor state");
    write(&root, "tor/data/cached-microdescs", "consensus cache");

    aero_core::update::stage(&archive, &root).expect("a real release archive should stage cleanly");
    let installed =
        aero_core::update::apply(&root).expect("a real release archive should install cleanly");
    eprintln!("installed {installed} files");
    assert!(
        installed > 20,
        "a real release has more than {installed} files in it"
    );

    // The application is the released one now.
    let exe = std::fs::metadata(root.join("aero_gui.exe")).expect("aero_gui.exe");
    assert!(exe.len() > 1_000_000, "aero_gui.exe should be the real binary");
    let core = std::fs::metadata(root.join("aero_core.dll")).expect("aero_core.dll");
    assert!(core.len() > 1_000_000, "aero_core.dll should be the real library");
    assert!(root.join("tor/tor.exe").exists(), "Tor should be installed");
    assert!(
        root.join("platforms/qwindows.dll").exists(),
        "Qt platform plugins should be installed"
    );

    // Every byte of the user's data is still there.
    assert_eq!(read(&root, "wallets/wallet/wallet.keys"), "ENCRYPTED KEYSTORE");
    assert_eq!(read(&root, "wallets/wallet_5/wallet_5.keys"), "ANOTHER KEYSTORE");
    assert_eq!(read(&root, "config/Aero/Aero.ini"), "[tor]\nexternal=false");
    assert_eq!(read(&root, "thp-pairing.txt"), "trezor credential");
    assert_eq!(read(&root, "tor/data/state"), "tor state");
    assert_eq!(read(&root, "tor/data/cached-microdescs"), "consensus cache");
    // Losing this one silently moves the next launch's data to Documents.
    assert!(root.join("portable").exists(), "the portable marker must survive");

    // And the previous version is still recoverable until the next launch sweeps it.
    assert_eq!(
        read(&root, ".aero-update/old/aero_gui.exe"),
        "PREVIOUS VERSION"
    );
    aero_core::update::sweep(&root);
    assert!(!root.join(".aero-update/old").exists());
    assert_eq!(read(&root, "wallets/wallet/wallet.keys"), "ENCRYPTED KEYSTORE");

    let _ = std::fs::remove_dir_all(&root);
}
