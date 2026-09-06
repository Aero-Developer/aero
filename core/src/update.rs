// SPDX-License-Identifier: BSD-3-Clause
//! Signed in-place updates.
//!
//! The rule this module exists to enforce: **nothing is written into the application folder that
//! was not covered by a signature from the pinned Aero release key.** Everything else here -
//! downloads, zips, renames - is plumbing arranged so that rule cannot be sidestepped.
//!
//! The chain, in order:
//!
//! 1. Fetch `aero-update.json` and `aero-update.json.asc` over Tor.
//! 2. Verify the detached signature against the key compiled into this binary ([`crate::pgp`]).
//!    Nothing in the manifest is even parsed until this passes, so a hostile file gets no chance to
//!    steer anything.
//! 3. Require the manifest's version to be strictly newer than the running one. A validly signed
//!    *old* release is still an attack - it is how you get someone back onto a version whose bugs
//!    you know.
//! 4. Download the archive, and require its length and SHA-256 to be exactly what the signed
//!    manifest said. The signature covers the manifest; the manifest's hash covers the archive.
//! 5. Extract to a staging folder, refusing any entry that escapes it or that names user data.
//! 6. Swap the staged files in, keeping the old ones until the next launch so a failure can be
//!    undone.
//!
//! The user's data is never a participant in any of this. `wallets/`, `config/`, the Trezor pairing
//! file and Tor's state are refused at extraction and skipped at install, so a release archive
//! cannot overwrite them even by accident and a malicious one cannot reach them at all.

use crate::error::{CoreError, Result};
use crate::pgp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Where signed releases live. `latest/download` always resolves to the newest published release,
/// so the app never has to be told a version number in advance.
const RELEASE_BASE: &str = "https://github.com/Aero-Developer/aero/releases/latest/download";

/// The signed manifest and its detached signature.
const MANIFEST: &str = "aero-update.json";
const MANIFEST_SIG: &str = "aero-update.json.asc";

/// Ceiling on what will be pulled down. Aero's portable zip is tens of megabytes; this is only here
/// so a server that answers a download with an endless stream runs out of welcome rather than disk.
const MAX_ARCHIVE_BYTES: u64 = 300 * 1024 * 1024;

/// Ceiling on the manifest, which is a few hundred bytes of JSON.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// Folder inside the application directory used for downloads, staging and the displaced old files.
const WORK_DIR: &str = ".aero-update";

/// Paths an update may never write to, create or replace, matched on the first path component.
///
/// This is the same list `ci/release.ps1` strips before packaging, enforced again at the other end.
/// The release script protects the developer from publishing a wallet; this protects the user from
/// an archive that contains one - whether through a packaging mistake or on purpose.
const PROTECTED: &[&str] = &[
    "wallets",         // encrypted keystores - the whole point of the wallet
    "config",          // QSettings: nodes, pins, privacy choices
    "thp-pairing.txt", // Trezor pairing credential
    "netlog.txt",
    WORK_DIR,
];

/// Files that are protected only in a nested position: Tor's state directory lives under `tor/`,
/// which otherwise does need updating (`tor.exe`, geoip data).
const PROTECTED_NESTED: &[&str] = &["tor/data"];

/// Extensions that are always user data, wherever they appear.
const PROTECTED_EXTENSIONS: &[&str] = &["keys", "aero", "plume"];

/// What a signed manifest says about a release.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    /// Release version, e.g. "0.1.28".
    pub version: String,
    /// Archive file name, resolved against the release base URL.
    pub file: String,
    /// Lower-case hex SHA-256 of the archive.
    pub sha256: String,
    /// Exact archive length in bytes.
    pub size: u64,
    /// Optional human-readable release notes shown before installing.
    #[serde(default)]
    pub notes: String,
}

/// The answer to "is there an update?", in a form the UI can show without knowing any of the above.
///
/// Round-trips through JSON across the FFI boundary, which is why it deserializes too. It is not a
/// capability: [`download`] re-checks the length and hash it carries against the bytes that arrive,
/// so a status that came back altered gets the download rejected rather than obeyed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub current: String,
    pub latest: String,
    pub available: bool,
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub notes: String,
    /// Fingerprint of the key the manifest was actually signed with, for display.
    pub signed_by: String,
    /// When the signature was made (unix seconds).
    pub signed_at: u64,
}

/// A version as compared for update purposes.
///
/// Deliberately a plain numeric triple. Pre-release suffixes and build metadata are not accepted
/// rather than being guessed at, because "is this newer" is the question that decides whether code
/// gets replaced, and a comparison nobody can predict is worse than no comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u32, u32, u32);

impl Version {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().trim_start_matches('v');
        let mut parts = s.split('.');
        let mut next = |what: &str| -> Result<u32> {
            parts
                .next()
                .and_then(|p| p.parse::<u32>().ok())
                .ok_or_else(|| CoreError::other(format!("version \"{s}\" has no {what} number")))
        };
        let major = next("major")?;
        let minor = next("minor")?;
        let patch = next("patch")?;
        if parts.next().is_some() {
            return Err(CoreError::other(format!(
                "version \"{s}\" has more than three parts"
            )));
        }
        Ok(Version(major, minor, patch))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

// ---- Fetching ----------------------------------------------------------------------------------

/// An HTTP client for update traffic.
///
/// Built here rather than borrowed from the wallet provider, because checking for updates has to
/// work when no wallet is open and no chain is connected. It keeps the wallet's rules: no ambient
/// system proxy, Tor Browser's user agent, and `socks5h` so the hostname is resolved through Tor
/// rather than by the local resolver.
fn client(socks: Option<&str>, timeout: Duration) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")
        .no_proxy();
    match socks {
        Some(p) if !p.trim().is_empty() => {
            let p = p.trim();
            let url = if p.contains("://") {
                p.replace("socks5://", "socks5h://")
            } else {
                format!("socks5h://{p}")
            };
            // A distinct SOCKS username keeps update traffic on its own Tor circuit, so the exit
            // that learns this machine is checking for an Aero update is not the exit handling its
            // wallet queries.
            let url = url.replace("socks5h://", "socks5h://aeroupdate:x@");
            b = b.proxy(
                reqwest::Proxy::all(&url)
                    .map_err(|e| CoreError::other(format!("bad Tor proxy for updates: {e}")))?,
            );
        }
        _ => {
            // No Tor. Updates are fetched from GitHub over TLS; the signature is what makes the
            // download trustworthy, but the connection would still reveal that this machine runs
            // Aero. The caller decides whether that is acceptable.
        }
    }
    b.build()
        .map_err(|e| CoreError::other(format!("update http client: {e}")))
}

async fn get(client: &reqwest::Client, url: &str, limit: u64) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CoreError::other(format!("could not reach the update server: {e}")))?;
    if !resp.status().is_success() {
        return Err(CoreError::other(format!(
            "update server answered {} for {url}",
            resp.status()
        )));
    }
    // Trust the declared length only as an early exit; the read below is what actually bounds us.
    if let Some(len) = resp.content_length() {
        if len > limit {
            return Err(CoreError::other(format!(
                "update download is {len} bytes, more than the {limit}-byte limit"
            )));
        }
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| CoreError::other(format!("update download failed: {e}")))?;
    if body.len() as u64 > limit {
        return Err(CoreError::other(
            "update download exceeded its size limit".to_string(),
        ));
    }
    Ok(body.to_vec())
}

/// Ask whether a newer signed release exists.
///
/// `current` is the running application's version. Returns an [`UpdateStatus`] whose `available`
/// flag is the only thing a caller should act on - a manifest that fails any check produces an
/// error, never an `available: false`, so a broken signature can never be mistaken for "up to date".
pub async fn check(current: &str, socks: Option<&str>) -> Result<UpdateStatus> {
    check_at(RELEASE_BASE, current, socks, &pgp::Verifier::release()).await
}

/// [`check`], with the release location and the trusted key given explicitly.
///
/// Only the tests pass anything but the pinned release key and the real release URL. Keeping the
/// substitution here rather than in a setting is the point: an updater whose trusted key can be
/// changed at runtime has no trusted key.
async fn check_at(
    base: &str,
    current: &str,
    socks: Option<&str>,
    verifier: &pgp::Verifier,
) -> Result<UpdateStatus> {
    let current_v = Version::parse(current)?;
    let http = client(socks, Duration::from_secs(60))?;

    let manifest_bytes = get(&http, &format!("{base}/{MANIFEST}"), MAX_MANIFEST_BYTES).await?;
    let sig_bytes = get(&http, &format!("{base}/{MANIFEST_SIG}"), MAX_MANIFEST_BYTES).await?;
    let sig = String::from_utf8(sig_bytes)
        .map_err(|_| CoreError::other("update signature is not text".to_string()))?;

    read_manifest(&manifest_bytes, &sig, current_v, verifier)
}

/// Verify a manifest and turn it into an [`UpdateStatus`].
///
/// Split out from [`check`] so the signature-then-parse ordering, the field checks and the version
/// comparison can be tested exhaustively without a network in the way. The tests substitute their
/// own `verifier`; the application only ever passes the pinned release key.
fn read_manifest(
    manifest_bytes: &[u8],
    sig: &str,
    current_v: Version,
    verifier: &pgp::Verifier,
) -> Result<UpdateStatus> {
    // Verify FIRST. Nothing below this line has looked at the manifest's contents, which is the
    // property that makes the rest of this function safe to write in the ordinary way.
    let signed_at = verifier.verify(manifest_bytes, sig)?;

    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| CoreError::other(format!("signed update manifest is not valid: {e}")))?;
    let latest = Version::parse(&manifest.version)?;

    // The archive name is used to build a URL and, later, to name files on disk. A signed manifest
    // is not a reason to skip checking it - the check costs nothing and the alternative is trusting
    // that the release process never once produces a path with a slash in it.
    if manifest.file.is_empty()
        || manifest.file.contains('/')
        || manifest.file.contains('\\')
        || manifest.file.contains("..")
    {
        return Err(CoreError::other(format!(
            "update manifest names a suspicious file \"{}\"",
            manifest.file
        )));
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreError::other(
            "update manifest does not carry a SHA-256 hash".to_string(),
        ));
    }
    if manifest.size == 0 || manifest.size > MAX_ARCHIVE_BYTES {
        return Err(CoreError::other(format!(
            "update manifest declares an implausible size of {} bytes",
            manifest.size
        )));
    }

    Ok(UpdateStatus {
        current: current_v.to_string(),
        latest: latest.to_string(),
        available: latest > current_v,
        file: manifest.file,
        sha256: manifest.sha256.to_lowercase(),
        size: manifest.size,
        notes: manifest.notes,
        signed_by: pgp::release_fingerprint_display(),
        signed_at,
    })
}

/// Bytes fetched so far, and the total expected, for a download in flight.
///
/// Plain atomics polled by the UI, matching how the funded-address scan already reports progress.
/// A download over Tor takes long enough that a window with no sign of life reads as a hang.
pub static DOWNLOADED: AtomicU64 = AtomicU64::new(0);
pub static DOWNLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Set to abandon a download in flight.
///
/// A release is tens of megabytes and Tor can make that take a long time, so the progress dialog has
/// a Cancel button; without this it would be a button that hides the window and lets the update
/// install anyway. Only the download is interruptible - once the files are being moved into place,
/// stopping half way is worse than finishing, so [`apply`] does not look at this.
static CANCEL: AtomicBool = AtomicBool::new(false);

/// Ask the download in flight to stop. Harmless when nothing is downloading.
pub fn cancel() {
    CANCEL.store(true, Ordering::Relaxed);
}

/// True when a failure was the user's own doing, so callers can stay quiet about it rather than
/// reporting a pressed button as an error.
pub fn was_cancelled(message: &str) -> bool {
    message.contains(CANCELLED)
}

const CANCELLED: &str = "update download cancelled";

/// Download the release archive named by an already-verified [`UpdateStatus`] and check it against
/// the hash the signed manifest gave. Returns the path it was written to.
pub async fn download(status: &UpdateStatus, app_dir: &Path, socks: Option<&str>) -> Result<PathBuf> {
    download_at(RELEASE_BASE, status, app_dir, socks, &CANCEL).await
}

/// [`download`], with the release location and the cancellation flag given explicitly.
///
/// The flag is a parameter rather than always the global one so that a test can cancel its own
/// download without cancelling every other download in the process - the tests run in parallel, and
/// one of them reaching into a static that another is reading is how a suite starts failing in ways
/// that have nothing to do with the code under test.
async fn download_at(
    base: &str,
    status: &UpdateStatus,
    app_dir: &Path,
    socks: Option<&str>,
    cancel: &AtomicBool,
) -> Result<PathBuf> {
    let http = client(socks, Duration::from_secs(1800))?;
    let url = format!("{base}/{}", status.file);

    DOWNLOADED.store(0, Ordering::Relaxed);
    DOWNLOAD_TOTAL.store(status.size, Ordering::Relaxed);
    // Cleared here rather than after a download, so a cancel left over from a previous attempt
    // cannot silently kill the next one.
    cancel.store(false, Ordering::Relaxed);

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| CoreError::other(format!("could not reach the update server: {e}")))?;
    if !resp.status().is_success() {
        return Err(CoreError::other(format!(
            "update server answered {} for the release archive",
            resp.status()
        )));
    }

    // Read in chunks rather than in one go: it is the only way to report progress, and it means a
    // server that keeps sending is cut off at the size limit instead of being buffered first.
    let mut bytes: Vec<u8> = Vec::with_capacity(status.size.min(MAX_ARCHIVE_BYTES) as usize);
    let mut stream = resp;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| CoreError::other(format!("update download failed: {e}")))?
    {
        if cancel.swap(false, Ordering::Relaxed) {
            return Err(CoreError::other(CANCELLED.to_string()));
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > status.size {
            return Err(CoreError::other(
                "update download is longer than the signed manifest said".to_string(),
            ));
        }
        DOWNLOADED.store(bytes.len() as u64, Ordering::Relaxed);
    }

    if bytes.len() as u64 != status.size {
        return Err(CoreError::other(format!(
            "downloaded update is {} bytes but the signed manifest said {}",
            bytes.len(),
            status.size
        )));
    }
    let got = hex::encode(Sha256::digest(&bytes));
    if got != status.sha256 {
        return Err(CoreError::other(format!(
            "downloaded update does not match its signed hash (expected {}, got {got}) - it was \
             corrupted or replaced in transit",
            status.sha256
        )));
    }

    let work = app_dir.join(WORK_DIR);
    std::fs::create_dir_all(&work)
        .map_err(|e| CoreError::other(format!("cannot create {}: {e}", work.display())))?;
    let path = work.join(&status.file);
    std::fs::write(&path, &bytes)
        .map_err(|e| CoreError::other(format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

// ---- Staging -----------------------------------------------------------------------------------

/// True if `rel` names something an update must not touch.
fn is_protected(rel: &Path) -> bool {
    let lower: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    if lower.is_empty() {
        return true;
    }
    if PROTECTED.iter().any(|p| lower[0] == *p) {
        return true;
    }
    let joined = lower.join("/");
    if PROTECTED_NESTED
        .iter()
        .any(|p| joined == *p || joined.starts_with(&format!("{p}/")))
    {
        return true;
    }
    if let Some(ext) = rel.extension().and_then(|e| e.to_str()) {
        if PROTECTED_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }
    false
}

/// Turn an archive entry name into a path safely under `root`, or refuse it.
///
/// Zip entries are attacker-controlled strings, and the classic trick is a name like
/// `../../wallets/wallet.keys` that writes outside the folder it was extracted into. Absolute paths,
/// drive letters and parent traversals are all refused rather than normalised, because there is no
/// legitimate release archive that contains any of them.
fn safe_entry_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        return Err(CoreError::other("update archive has an unnamed entry".to_string()));
    }
    let raw = name.replace('\\', "/");
    if raw.starts_with('/') || raw.contains(':') {
        return Err(CoreError::other(format!(
            "update archive contains an absolute path ({name}); refusing to extract it"
        )));
    }
    let mut out = PathBuf::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(CoreError::other(format!(
                "update archive tries to escape its folder ({name}); refusing to extract it"
            )));
        }
        // Windows silently drops trailing dots and spaces when resolving a path, so `wallets.` and
        // `wallets ` both name the `wallets` folder while comparing unequal to it. Refusing the
        // spelling is simpler than trying to guess which names collapse onto a protected one, and no
        // real archive contains them.
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(CoreError::other(format!(
                "update archive entry \"{name}\" has a trailing dot or space; refusing it"
            )));
        }
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        return Err(CoreError::other("update archive has an empty entry name".to_string()));
    }
    if is_protected(&out) {
        return Err(CoreError::other(format!(
            "update archive tries to write {name}, which is your data, not Aero's - refusing the \
             whole archive"
        )));
    }
    Ok(out)
}

/// Extract a verified archive into `<app_dir>/.aero-update/staged`, returning that folder.
///
/// Called only after [`download`] has matched the archive against the signed hash, so the bytes
/// here are known-good. The checks in [`safe_entry_path`] are still applied: a signature says who
/// built the archive, not that the build was correct.
pub fn stage(archive: &Path, app_dir: &Path) -> Result<PathBuf> {
    let staged = app_dir.join(WORK_DIR).join("staged");
    if staged.exists() {
        std::fs::remove_dir_all(&staged)
            .map_err(|e| CoreError::other(format!("cannot clear {}: {e}", staged.display())))?;
    }
    std::fs::create_dir_all(&staged)
        .map_err(|e| CoreError::other(format!("cannot create {}: {e}", staged.display())))?;

    let file = std::fs::File::open(archive)
        .map_err(|e| CoreError::other(format!("cannot open {}: {e}", archive.display())))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| CoreError::other(format!("update archive is not a readable zip: {e}")))?;

    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| CoreError::other(format!("update archive entry {i} is unreadable: {e}")))?;
        let name = entry.name().to_string();
        if entry.is_dir() {
            // Still validated, so a directory entry cannot be the thing that creates `../wallets`.
            let rel = safe_entry_path(name.trim_end_matches('/'))?;
            std::fs::create_dir_all(staged.join(rel))
                .map_err(|e| CoreError::other(format!("cannot create folder in staging: {e}")))?;
            continue;
        }
        let rel = safe_entry_path(&name)?;

        // Guard the uncompressed total, not just the download. A zip bomb is small on the wire.
        total = total.saturating_add(entry.size());
        if total > MAX_ARCHIVE_BYTES {
            return Err(CoreError::other(
                "update archive expands to more than the size limit; refusing it".to_string(),
            ));
        }

        let target = staged.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CoreError::other(format!("cannot create {}: {e}", parent.display())))?;
        }
        let mut buf = Vec::with_capacity(entry.size().min(8 * 1024 * 1024) as usize);
        entry
            .read_to_end(&mut buf)
            .map_err(|e| CoreError::other(format!("cannot read {name} from the archive: {e}")))?;
        std::fs::write(&target, &buf)
            .map_err(|e| CoreError::other(format!("cannot write {}: {e}", target.display())))?;

        // Carry the executable bit across. Windows does not have one, but a macOS or Linux build
        // installed without it would replace a working Aero with a file the system refuses to run -
        // and the user would have no application left to update from.
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
        }
    }

    // An archive with no executable in it is not an Aero release, whatever it is signed with.
    let has_app = staged.join("aero_gui.exe").exists() || staged.join("aero_gui").exists();
    if !has_app {
        return Err(CoreError::other(
            "update archive does not contain the Aero application; refusing it".to_string(),
        ));
    }
    Ok(staged)
}

// ---- Installing --------------------------------------------------------------------------------

/// Install the staged files over the application folder.
///
/// Windows will not let a running executable be deleted or overwritten, but it will happily let it
/// be **renamed**. So each file about to be replaced is moved aside into `.aero-update/old` and the
/// new one is moved into the gap. That is why this needs no second process, no helper script and no
/// scheduled task - which also keeps Aero from doing the one thing that most looks like malware to
/// an antivirus: writing a program that rewrites the program.
///
/// If any step fails, everything already moved is moved back, so the installation is all or nothing.
/// The displaced originals stay on disk until the next launch, when [`sweep`] removes them - by then
/// the old executable is no longer running and can actually be deleted.
pub fn apply(app_dir: &Path) -> Result<usize> {
    let staged = app_dir.join(WORK_DIR).join("staged");
    if !staged.is_dir() {
        return Err(CoreError::other(
            "no staged update to install".to_string(),
        ));
    }
    let backup = app_dir.join(WORK_DIR).join("old");
    if backup.exists() {
        let _ = std::fs::remove_dir_all(&backup);
    }
    std::fs::create_dir_all(&backup)
        .map_err(|e| CoreError::other(format!("cannot create {}: {e}", backup.display())))?;

    let mut files = Vec::new();
    collect(&staged, &staged, &mut files)?;

    // (relative path, was there an original that got moved aside?)
    let mut done: Vec<(PathBuf, bool)> = Vec::new();
    for rel in &files {
        if is_protected(rel) {
            continue; // belt and braces; stage() already refused these
        }
        let target = app_dir.join(rel);
        let source = staged.join(rel);
        let result = (|| -> std::io::Result<bool> {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let displaced = target.exists();
            if displaced {
                let aside = backup.join(rel);
                if let Some(parent) = aside.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(&target, &aside)?;
            }
            std::fs::rename(&source, &target)?;
            Ok(displaced)
        })();

        match result {
            Ok(displaced) => done.push((rel.clone(), displaced)),
            Err(e) => {
                // Put everything back before reporting, so a half-installed folder never survives.
                for (undo, had_original) in done.iter().rev() {
                    let target = app_dir.join(undo);
                    let _ = std::fs::rename(&target, staged.join(undo));
                    if *had_original {
                        let _ = std::fs::rename(backup.join(undo), &target);
                    }
                }
                return Err(CoreError::other(format!(
                    "could not install {}: {e}. Nothing was changed - close Aero and try again.",
                    rel.display()
                )));
            }
        }
    }

    let _ = std::fs::remove_dir_all(&staged);
    Ok(done.len())
}

/// Remove what the last update displaced. Safe to call at startup; does nothing if there is none.
///
/// This is the other half of the rename trick: the previous executable could not be deleted while it
/// was the one running, so it was only moved. By the time this runs, the new one is running instead
/// and the old files are just files.
pub fn sweep(app_dir: &Path) {
    let work = app_dir.join(WORK_DIR);
    if !work.exists() {
        return;
    }
    let _ = std::fs::remove_dir_all(work.join("old"));
    let _ = std::fs::remove_dir_all(work.join("staged"));
    // Downloaded archives are large and of no further use once installed.
    if let Ok(entries) = std::fs::read_dir(&work) {
        for e in entries.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) == Some("zip") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    // Leave the folder itself: it is cheap, and removing it races with a check already running.
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CoreError::other(format!("cannot read {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number_not_by_text() {
        assert!(Version::parse("0.1.28").unwrap() > Version::parse("0.1.27").unwrap());
        // The comparison that a string sort gets wrong, and the reason this is not a string sort.
        assert!(Version::parse("0.1.100").unwrap() > Version::parse("0.1.99").unwrap());
        assert!(Version::parse("0.2.0").unwrap() > Version::parse("0.1.999").unwrap());
        assert!(Version::parse("1.0.0").unwrap() > Version::parse("0.99.99").unwrap());
        assert_eq!(
            Version::parse("v0.1.27").unwrap(),
            Version::parse("0.1.27").unwrap()
        );
        // Equal is not newer: re-installing the running version is not an update.
        assert!(!(Version::parse("0.1.27").unwrap() > Version::parse("0.1.27").unwrap()));
    }

    #[test]
    fn a_version_that_cannot_be_compared_is_refused_rather_than_guessed() {
        for bad in ["", "0.1", "0.1.2.3", "1.2.x", "latest", "0.1.2-rc1", "-1.0.0"] {
            assert!(
                Version::parse(bad).is_err(),
                "\"{bad}\" should not parse into something comparable"
            );
        }
    }

    /// The escape attempts an archive could make. Each of these, if allowed through, writes outside
    /// the staging folder - and the most valuable place to land is the wallet folder.
    #[test]
    fn an_archive_cannot_escape_its_folder() {
        for bad in [
            "../evil.exe",
            "../../evil.exe",
            "a/../../evil.exe",
            "/etc/passwd",
            "C:/Windows/System32/evil.dll",
            "..\\..\\evil.exe",
            "foo/../../../bar",
            "",
            // Windows resolves all four of these to the `wallets` folder, while none of them is
            // the string "wallets". The protected-name check compares strings, so the spelling has
            // to be refused for that check to mean anything.
            "wallets./wallet.keys",
            "wallets /wallet.keys",
            "wallets../wallet.keys",
            "config./Aero/Aero.ini",
        ] {
            assert!(
                safe_entry_path(bad).is_err(),
                "\"{bad}\" should have been refused"
            );
        }
        // And the ordinary names a real release contains still work.
        for good in ["aero_gui.exe", "tor/tor.exe", "platforms/qwindows.dll", "./run.bat"] {
            assert!(
                safe_entry_path(good).is_ok(),
                "\"{good}\" should be a valid entry"
            );
        }
    }

    /// An update must not be able to touch the user's data even when it asks nicely, with a
    /// perfectly ordinary relative path and a valid signature.
    #[test]
    fn an_update_can_never_write_over_user_data() {
        for protected in [
            "wallets/wallet/wallet.keys",
            "wallets",
            "config/Aero/Aero.ini",
            "config",
            "thp-pairing.txt",
            "tor/data/state",
            "tor/data",
            "some/where/secret.keys",
            "old.aero",
            "backup.plume",
            ".aero-update/staged/x",
        ] {
            assert!(
                safe_entry_path(protected).is_err(),
                "\"{protected}\" is user data and must be refused"
            );
        }
        // Tor's program files are still updatable - only its state directory is off limits.
        assert!(safe_entry_path("tor/tor.exe").is_ok());
        assert!(safe_entry_path("tor/geoip").is_ok());
    }

    /// Case matters on Windows only in that it does not: `WALLETS` and `wallets` are the same
    /// folder, so the guard has to treat them the same way.
    #[test]
    fn the_data_guard_is_not_fooled_by_capitals() {
        for shouty in ["WALLETS/x.keys", "Config/Aero.ini", "TOR/DATA/state", "a.KEYS"] {
            assert!(
                safe_entry_path(shouty).is_err(),
                "\"{shouty}\" should be refused regardless of case"
            );
        }
    }

    // ---- Whole-chain tests ------------------------------------------------------------------
    //
    // Everything below runs the real code end to end: a real Ed25519 key, a real OpenPGP signature
    // over a real manifest, a real zip, extracted and installed into a real folder on disk.

    use pgp_test_support::{sign_manifest, TestSigner};

    /// A scratch folder that cleans up after itself.
    struct Temp(PathBuf);

    impl Temp {
        fn new(tag: &str) -> Self {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("aero-update-test-{tag}-{n}"));
            std::fs::create_dir_all(&p).expect("temp dir");
            Temp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn read(root: &Path, rel: &str) -> String {
        std::fs::read_to_string(root.join(rel)).unwrap_or_default()
    }

    /// Build a zip whose entries are exactly `files`.
    fn make_zip(at: &Path, files: &[(&str, &str)]) -> PathBuf {
        let path = at.join("release.zip");
        let file = std::fs::File::create(&path).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in files {
            use std::io::Write;
            w.start_file(*name, opts).unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap();
        path
    }

    /// An application folder that has been used: it has the app in it, and it has the user's data.
    fn installed_app(root: &Path) {
        write(root, "aero_gui.exe", "OLD APP v0.1.27");
        write(root, "aero_core.dll", "OLD CORE");
        write(root, "Qt6Core.dll", "OLD QT");
        write(root, "platforms/qwindows.dll", "OLD PLATFORM");
        write(root, "tor/tor.exe", "OLD TOR");
        // The things that must survive, whatever else happens.
        write(root, "wallets/wallet/wallet.keys", "ENCRYPTED KEYS - DO NOT LOSE");
        write(root, "wallets/wallet_2/wallet_2.keys", "MORE KEYS");
        write(root, "config/Aero/Aero.ini", "[privacy]\nallowClearnetLinks=false");
        write(root, "thp-pairing.txt", "trezor pairing credential");
        write(root, "tor/data/state", "tor circuit state");
    }

    /// The whole point of the feature: install a new version, keep every byte of the user's data.
    #[test]
    fn an_update_replaces_the_app_and_leaves_the_wallets_alone() {
        let app = Temp::new("install");
        installed_app(app.path());

        let src = Temp::new("src");
        let zip = make_zip(
            src.path(),
            &[
                ("aero_gui.exe", "NEW APP v0.1.28"),
                ("aero_core.dll", "NEW CORE"),
                ("Qt6Core.dll", "NEW QT"),
                ("platforms/qwindows.dll", "NEW PLATFORM"),
                ("tor/tor.exe", "NEW TOR"),
                ("run.bat", "@echo off"), // a file the old install did not have
            ],
        );

        stage(&zip, app.path()).expect("staging should succeed");
        let installed = apply(app.path()).expect("install should succeed");
        assert_eq!(installed, 6, "every file in the archive should be installed");

        // The application is now the new one, including a file that did not exist before.
        assert_eq!(read(app.path(), "aero_gui.exe"), "NEW APP v0.1.28");
        assert_eq!(read(app.path(), "aero_core.dll"), "NEW CORE");
        assert_eq!(read(app.path(), "Qt6Core.dll"), "NEW QT");
        assert_eq!(read(app.path(), "platforms/qwindows.dll"), "NEW PLATFORM");
        assert_eq!(read(app.path(), "tor/tor.exe"), "NEW TOR");
        assert_eq!(read(app.path(), "run.bat"), "@echo off");

        // And the user's data is exactly as it was.
        assert_eq!(
            read(app.path(), "wallets/wallet/wallet.keys"),
            "ENCRYPTED KEYS - DO NOT LOSE"
        );
        assert_eq!(read(app.path(), "wallets/wallet_2/wallet_2.keys"), "MORE KEYS");
        assert_eq!(
            read(app.path(), "config/Aero/Aero.ini"),
            "[privacy]\nallowClearnetLinks=false"
        );
        assert_eq!(read(app.path(), "thp-pairing.txt"), "trezor pairing credential");
        assert_eq!(read(app.path(), "tor/data/state"), "tor circuit state");

        // The old binaries are still around so a failure could be undone, until the next launch.
        assert!(app.path().join(WORK_DIR).join("old/aero_gui.exe").exists());
        sweep(app.path());
        assert!(!app.path().join(WORK_DIR).join("old").exists());
        // Sweeping removes the leftovers and nothing else.
        assert_eq!(read(app.path(), "aero_gui.exe"), "NEW APP v0.1.28");
        assert_eq!(
            read(app.path(), "wallets/wallet/wallet.keys"),
            "ENCRYPTED KEYS - DO NOT LOSE"
        );
    }

    /// An archive that reaches for the wallet folder is refused whole. Not filtered, not partially
    /// applied - refused, because an archive that contains that entry is not a release Aero made.
    #[test]
    fn an_archive_that_reaches_for_the_wallets_is_refused_entirely() {
        let app = Temp::new("hostile");
        installed_app(app.path());

        let src = Temp::new("hostile-src");
        for hostile in [
            "wallets/wallet/wallet.keys",
            "../wallets/wallet/wallet.keys",
            "config/Aero/Aero.ini",
        ] {
            let zip = make_zip(
                src.path(),
                &[("aero_gui.exe", "NEW APP"), (hostile, "STOLEN")],
            );
            assert!(
                stage(&zip, app.path()).is_err(),
                "an archive containing {hostile} must be refused"
            );
        }

        // Nothing was touched: not the app, and certainly not the keys.
        assert_eq!(read(app.path(), "aero_gui.exe"), "OLD APP v0.1.27");
        assert_eq!(
            read(app.path(), "wallets/wallet/wallet.keys"),
            "ENCRYPTED KEYS - DO NOT LOSE"
        );
        assert_eq!(
            read(app.path(), "config/Aero/Aero.ini"),
            "[privacy]\nallowClearnetLinks=false"
        );
    }

    /// An archive without the application in it is not a release, however well formed it is.
    #[test]
    fn an_archive_without_the_app_is_refused() {
        let app = Temp::new("noapp");
        installed_app(app.path());
        let src = Temp::new("noapp-src");
        let zip = make_zip(src.path(), &[("readme.txt", "hello")]);
        assert!(stage(&zip, app.path()).is_err());
        assert_eq!(read(app.path(), "aero_gui.exe"), "OLD APP v0.1.27");
    }

    /// A signed manifest for a newer version is an update; the same manifest checked by a newer
    /// build is not. A signed *older* release must never be installed - that is a rollback, and it
    /// is how a working attack gets you back onto a version whose weaknesses are already known.
    #[test]
    fn only_a_newer_signed_version_counts_as_an_update() {
        let signer = TestSigner::new();
        let manifest = br#"{"version":"0.1.28","file":"Aero-0.1.28-Windows-x64-portable.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1024,"notes":"Fixes"}"#;
        let sig = sign_manifest(&signer, manifest);
        let verifier = crate::pgp::verifier_for_tests(signer.public_key());

        let older = read_manifest(manifest, &sig, Version::parse("0.1.27").unwrap(), &verifier)
            .expect("valid manifest");
        assert!(older.available, "0.1.28 is newer than 0.1.27");
        assert_eq!(older.latest, "0.1.28");
        assert_eq!(older.notes, "Fixes");

        let same = read_manifest(manifest, &sig, Version::parse("0.1.28").unwrap(), &verifier)
            .expect("valid manifest");
        assert!(!same.available, "the running version is not an update");

        let newer = read_manifest(manifest, &sig, Version::parse("0.1.29").unwrap(), &verifier)
            .expect("valid manifest");
        assert!(!newer.available, "a signed older release must never be offered");
    }

    /// The check that matters most: an attacker who can serve any file they like still cannot get
    /// one installed, because they cannot produce a signature from the pinned key.
    #[test]
    fn an_unsigned_or_wrongly_signed_manifest_is_never_an_update() {
        let signer = TestSigner::new();
        let attacker = TestSigner::new();
        let verifier = crate::pgp::verifier_for_tests(signer.public_key());
        let manifest = br#"{"version":"9.9.9","file":"evil.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1024}"#;

        // Signed by someone else entirely.
        let forged = sign_manifest(&attacker, manifest);
        assert!(
            read_manifest(manifest, &forged, Version::parse("0.1.27").unwrap(), &verifier).is_err(),
            "a manifest signed by another key must be refused"
        );

        // Genuinely signed, then edited afterwards - the usual shape of a real attempt.
        let genuine = br#"{"version":"0.1.28","file":"Aero-0.1.28.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1024}"#;
        let sig = sign_manifest(&signer, genuine);
        let edited = br#"{"version":"0.1.28","file":"evil.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":1024}"#;
        assert!(
            read_manifest(edited, &sig, Version::parse("0.1.27").unwrap(), &verifier).is_err(),
            "swapping the archive name after signing must be refused"
        );

        // No signature at all.
        assert!(read_manifest(genuine, "", Version::parse("0.1.27").unwrap(), &verifier).is_err());
        assert!(read_manifest(
            genuine,
            "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----",
            Version::parse("0.1.27").unwrap(),
            &verifier
        )
        .is_err());
    }

    /// A signed manifest is trusted about *which* archive to install, but the fields still have to
    /// make sense. A release process that emits a path or a nonsense hash should fail loudly here
    /// rather than have the result used to build a URL and a filename.
    #[test]
    fn a_signed_manifest_still_has_to_be_sane() {
        let signer = TestSigner::new();
        let verifier = crate::pgp::verifier_for_tests(signer.public_key());
        let current = Version::parse("0.1.27").unwrap();
        let hash = "0".repeat(64);

        for bad in [
            format!(r#"{{"version":"0.1.28","file":"../evil.zip","sha256":"{hash}","size":10}}"#),
            format!(r#"{{"version":"0.1.28","file":"a/b.zip","sha256":"{hash}","size":10}}"#),
            format!(r#"{{"version":"0.1.28","file":"","sha256":"{hash}","size":10}}"#),
            format!(r#"{{"version":"0.1.28","file":"a.zip","sha256":"nothex","size":10}}"#),
            format!(r#"{{"version":"0.1.28","file":"a.zip","sha256":"{hash}","size":0}}"#),
            format!(
                r#"{{"version":"0.1.28","file":"a.zip","sha256":"{hash}","size":999999999999}}"#
            ),
            format!(r#"{{"version":"not-a-version","file":"a.zip","sha256":"{hash}","size":10}}"#),
            r#"not json at all"#.to_string(),
        ] {
            let sig = sign_manifest(&signer, bad.as_bytes());
            assert!(
                read_manifest(bad.as_bytes(), &sig, current, &verifier).is_err(),
                "manifest should have been refused: {bad}"
            );
        }
    }

    /// The whole thing, over a real socket: publish a signed release, have the updater find it,
    /// download it, check it, unpack it and install it, and confirm the wallet came through.
    ///
    /// The unit tests above each hold one piece still. This one holds nothing still - it is the
    /// closest thing to what will actually happen on a user's machine that can be run offline, and
    /// it is the test that would catch a mistake in how the pieces are wired to each other rather
    /// than in any one of them.
    #[test]
    fn a_published_release_is_found_downloaded_and_installed() {
        let app = Temp::new("e2e-app");
        installed_app(app.path());

        // Build the release exactly as ci/release.ps1 would: an archive, then a manifest naming it
        // and its hash, then a detached signature over the manifest.
        let publish = Temp::new("e2e-publish");
        let archive = make_zip(
            publish.path(),
            &[
                ("aero_gui.exe", "NEW APP v0.1.28"),
                ("aero_core.dll", "NEW CORE"),
                ("tor/tor.exe", "NEW TOR"),
            ],
        );
        let zip_bytes = std::fs::read(&archive).unwrap();
        let manifest = format!(
            r#"{{"version":"0.1.28","file":"Aero-0.1.28-Windows-x64-portable.zip","sha256":"{}","size":{},"notes":"Security fixes"}}"#,
            hex::encode(Sha256::digest(&zip_bytes)),
            zip_bytes.len()
        );
        let signer = TestSigner::new();
        let sig = sign_manifest(&signer, manifest.as_bytes());
        let verifier = crate::pgp::verifier_for_tests(signer.public_key());

        let base = serve(vec![
            ("/aero-update.json".to_string(), manifest.into_bytes()),
            ("/aero-update.json.asc".to_string(), sig.into_bytes()),
            (
                "/Aero-0.1.28-Windows-x64-portable.zip".to_string(),
                zip_bytes.clone(),
            ),
        ]);

        let rt = tokio::runtime::Runtime::new().unwrap();

        let status = rt
            .block_on(check_at(&base, "0.1.27", None, &verifier))
            .expect("the signed release should be found");
        assert!(status.available);
        assert_eq!(status.latest, "0.1.28");
        assert_eq!(status.notes, "Security fixes");

        let downloaded = rt
            .block_on(download_at(
                &base,
                &status,
                app.path(),
                None,
                &AtomicBool::new(false),
            ))
            .expect("download should verify against the signed hash");
        assert_eq!(std::fs::read(&downloaded).unwrap(), zip_bytes);
        // The progress counters are deliberately not asserted here: they are process-global,
        // because the application only ever runs one download at a time, and the tests do not.

        stage(&downloaded, app.path()).expect("stage");
        apply(app.path()).expect("install");

        assert_eq!(read(app.path(), "aero_gui.exe"), "NEW APP v0.1.28");
        assert_eq!(read(app.path(), "tor/tor.exe"), "NEW TOR");
        assert_eq!(
            read(app.path(), "wallets/wallet/wallet.keys"),
            "ENCRYPTED KEYS - DO NOT LOSE"
        );
        assert_eq!(read(app.path(), "tor/data/state"), "tor circuit state");

        // And the machine that just installed 0.1.28 is not offered it again.
        let after = rt
            .block_on(check_at(&base, "0.1.28", None, &verifier))
            .expect("check");
        assert!(!after.available);
    }

    /// Cancel stops the download and leaves nothing installed.
    ///
    /// The Cancel button on the progress dialog is the only way out of a download that Tor has made
    /// very slow, and a button that hides a window while the update carries on regardless is worse
    /// than no button at all. So: cancel, and check both that the download fails and that the
    /// failure is recognisable as the user's own doing rather than something to alarm them with.
    #[test]
    fn a_cancelled_download_stops_and_is_not_reported_as_a_failure() {
        let app = Temp::new("e2e-cancel");
        installed_app(app.path());

        // Incompressible bytes served slowly, so the cancel lands in the middle of a download that
        // is genuinely still running rather than racing a transfer that finished instantly.
        let body: Vec<u8> = (0..120_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let base = serve_slowly(
            vec![(
                "/Aero-0.1.28-Windows-x64-portable.zip".to_string(),
                body.clone(),
            )],
            started.clone(),
        );

        let status = UpdateStatus {
            available: true,
            latest: "0.1.28".to_string(),
            current: "0.1.27".to_string(),
            file: "Aero-0.1.28-Windows-x64-portable.zip".to_string(),
            sha256: hex::encode(Sha256::digest(&body)),
            size: body.len() as u64,
            notes: String::new(),
            signed_by: String::new(),
            signed_at: 0,
        };

        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let asked = flag.clone();
        let canceller = std::thread::spawn(move || {
            while !started.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(1));
            }
            asked.store(true, Ordering::Relaxed);
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(download_at(&base, &status, app.path(), None, &flag))
            .expect_err("a cancelled download must not succeed");
        canceller.join().unwrap();
        assert!(
            was_cancelled(&err.to_string()),
            "a cancelled download should say so, not report {err}"
        );
        assert!(
            !app.path().join(WORK_DIR).join(&status.file).exists(),
            "a cancelled download should leave no archive behind"
        );

        // And a cancel nobody acted on does not carry over. Left set, it would stop the *next*
        // download instead - a user who cancels once and then retries would find that Aero simply
        // refuses to update, with no indication why.
        flag.store(true, Ordering::Relaxed);
        rt.block_on(download_at(&base, &status, app.path(), None, &flag))
            .expect("a stale cancel must not stop the next download");
    }

    /// The same publication, with the archive swapped after the manifest was signed. This is what a
    /// compromised release host or a tampering mirror looks like: the signature is genuine, the
    /// manifest is genuine, and the file behind it is not the one that was signed for.
    #[test]
    fn an_archive_that_does_not_match_the_signed_hash_is_refused() {
        let app = Temp::new("e2e-swap");
        installed_app(app.path());

        let publish = Temp::new("e2e-swap-publish");
        let real = std::fs::read(make_zip(publish.path(), &[("aero_gui.exe", "REAL APP")])).unwrap();
        let manifest = format!(
            r#"{{"version":"0.1.28","file":"Aero-0.1.28-Windows-x64-portable.zip","sha256":"{}","size":{}}}"#,
            hex::encode(Sha256::digest(&real)),
            real.len()
        );
        let signer = TestSigner::new();
        let sig = sign_manifest(&signer, manifest.as_bytes());
        let verifier = crate::pgp::verifier_for_tests(signer.public_key());

        // Served: a different archive of the same length, so only the hash gives it away.
        let swapped = Temp::new("e2e-swap-evil");
        let mut evil =
            std::fs::read(make_zip(swapped.path(), &[("aero_gui.exe", "EVIL APP")])).unwrap();
        evil.resize(real.len(), 0);

        let base = serve(vec![
            ("/aero-update.json".to_string(), manifest.into_bytes()),
            ("/aero-update.json.asc".to_string(), sig.into_bytes()),
            ("/Aero-0.1.28-Windows-x64-portable.zip".to_string(), evil),
        ]);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let status = rt
            .block_on(check_at(&base, "0.1.27", None, &verifier))
            .expect("the manifest itself is genuine");
        assert!(status.available);

        let err = rt
            .block_on(download_at(
                &base,
                &status,
                app.path(),
                None,
                &AtomicBool::new(false),
            ))
            .expect_err("an archive that does not match its signed hash must be refused");
        assert!(
            err.to_string().contains("signed hash"),
            "the error should say why: {err}"
        );
        assert_eq!(read(app.path(), "aero_gui.exe"), "OLD APP v0.1.27");
    }

    /// A one-shot HTTP server over the given paths. Returns the base URL to fetch from.
    fn serve(files: Vec<(String, Vec<u8>)>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                match files.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(body);
                    }
                    None => {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                }
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// [`serve`], but dribbling the body out in small pieces and flipping `started` once the first
    /// one is on the wire. Cancellation can only be tested against a download that is still running.
    fn serve_slowly(files: Vec<(String, Vec<u8>)>, started: std::sync::Arc<AtomicBool>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let Some((_, body)) = files.iter().find(|(p, _)| *p == path) else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    continue;
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                for piece in body.chunks(4096) {
                    if stream.write_all(piece).is_err() || stream.flush().is_err() {
                        break;
                    }
                    started.store(true, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Signing and key handling for the tests, using rpgp so the signatures are produced by an
    /// implementation independent of the one being tested.
    mod pgp_test_support {
        use pgp::composed::{
            KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, StandaloneSignature,
        };
        use pgp::crypto::hash::HashAlgorithm;
        use pgp::crypto::public_key::PublicKeyAlgorithm;
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};

        pub struct TestSigner(SignedSecretKey);

        impl TestSigner {
            pub fn new() -> Self {
                let params = SecretKeyParamsBuilder::default()
                    .key_type(KeyType::EdDSALegacy)
                    .can_sign(true)
                    .primary_user_id("Aero Test <test@example.invalid>".into())
                    .build()
                    .expect("key params");
                TestSigner(
                    params
                        .generate(rand::thread_rng())
                        .expect("generate")
                        .sign(rand::thread_rng(), String::new)
                        .expect("self-sign"),
                )
            }

            pub fn public_key(&self) -> [u8; 32] {
                let armored = SignedPublicKey::from(self.0.clone())
                    .to_armored_string(Default::default())
                    .expect("armor");
                crate::pgp::ed25519_from_armored_key(&armored)
            }
        }

        pub fn sign_manifest(signer: &TestSigner, data: &[u8]) -> String {
            let mut config = SignatureConfig::v4(
                SignatureType::Binary,
                PublicKeyAlgorithm::EdDSALegacy,
                HashAlgorithm::SHA2_256,
            );
            config.hashed_subpackets = vec![Subpacket::regular(
                SubpacketData::SignatureCreationTime(chrono::Utc::now()),
            )];
            let sig = config
                .sign(&signer.0.primary_key, String::new, data)
                .expect("sign");
            StandaloneSignature::new(sig)
                .to_armored_string(Default::default())
                .expect("armor")
        }
    }
}
