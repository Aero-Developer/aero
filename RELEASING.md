# Releasing Aero

Aero is a wallet, so release integrity matters: users must be able to verify that the binary they
run is the one the maintainers published, unmodified. This document describes how releases are
built, checksummed, and signed, and how users verify a download.

## Principles

- **Deterministic inputs.** Builds pin the Rust toolchain (stable GNU), the exact `Cargo.lock`, and
  a fixed Qt version (6.8.2, MinGW). Anyone can reproduce the artifacts from a tagged commit.
- **No telemetry, no network at build time** beyond fetching pinned dependencies.
- **Every artifact is hashed and signed.** The release publishes `SHA256SUMS` and a detached
  signature over it.

## Build steps

From a clean checkout at the release tag:

```powershell
# 1. Core (Rust cdylib + import lib), reproducible from Cargo.lock
cd core
$env:RUSTFLAGS = "-C link-args=-lwinpthread"
cargo build --release --locked

# 2. Regenerate the C header (only needed if the FFI changed)
cbindgen --config cbindgen.toml --crate aero_core --output ../frontend/src/ethwallet/aero_core.h

# 3. GUI (Qt6 / MinGW)
cd ../frontend/gui/build
cmake .. -G "MinGW Makefiles"
mingw32-make -j

# 4. Assemble the portable folder (exe + aero_core.dll + tor/ + the `portable` marker)
#    into dist/aero-portable, then zip it.
```

`ci/release.ps1` zips a staging copy, never `dist/aero-portable` itself, and drops everything that
running Aero from that folder leaves behind: `wallets/`, `config/`, `thp-pairing.txt`, `netlog.txt`,
`.aero-update/` and `tor/data/`. That last one is the release machine's Tor identity - guard
selection, bandwidth history, `keys/`, and forty megabytes of consensus cache the user's own Tor
fetches anyway - and it is the only one of these that is easy to miss, because it hides inside a
folder that does ship. The script refuses to package if any of them survive, and the updater refuses
to install an archive containing them, so this is checked twice.

## The build has to start before it can ship

Before it writes the zip, `ci/release.ps1` runs the packaged `aero_gui.exe` on a throwaway copy of the
staging folder and waits for it to load Qt and `aero_core`. If it does not get there, the release is
refused.

0.1.29 exists because 0.1.28 did not have this. That release was built, staged, zipped, hashed,
signed and published without anyone once double-clicking it, and it could not start on any machine:
the linker had stamped the PE as demanding Win32 subsystem 10.0, and Windows refuses any ordinary
application asking for more than 6.2 with `0xc000007b`, before mapping a single DLL. Nothing in the
process noticed, because every check that release ran was a check on bytes - and the bytes were
exactly what was wrong. So the script now checks the subsystem version outright, and then runs the
program, which is the only check that could not have been passed by a binary that does not work.

The smoke test runs against a copy because a first launch writes `config/` and starts Tor, and none
of that may end up in the archive.

`cargo build --locked` fails if `Cargo.lock` would change, which is what makes the Rust half
reproducible. Record the toolchain versions in the release notes:

```powershell
rustc --version; cargo --version
```

## Checksums

Generate `SHA256SUMS` over every shipped artifact:

```powershell
pwsh scripts/release-checksums.ps1 -Dir dist
```

This writes `dist/SHA256SUMS` in the standard `<hash>  <path>` format.

## Signing

There is exactly one file to sign: **`dist/aero-update.json`**.

`ci/release.ps1` writes it after building the zip. It names the archive, its SHA-256 and its exact
size, so a signature over this one small file authorises the whole release. This is deliberately the
only signed artifact - a release process with two signatures is a release process where one of them
eventually gets forgotten, and the one that gets forgotten is the one that mattered.

The key is the Aero release key:

```
pub   ed25519 2026-09-05 [SC] [expires: 2029-09-05]
      FD06 516B 6C76 2BB8 B016  16DE 80D5 05C2 5B02 54B3
uid   Aero
```

Its public half is committed at `keys/aero-release.asc`, and the Ed25519 point from it is compiled
into every build (`core/src/pgp.rs`, `RELEASE_KEY`). **That pinned copy is the only key any build
will ever accept**, so rotating the key means shipping a new binary through some other channel -
plan for that before it is urgent, not after.

Sign it detached and armored:

```powershell
gpg --local-user FD06516B6C762BB8B01616DE80D505C25B0254B3 `
    --armor --detach-sign `
    --output dist/aero-update.json.asc dist/aero-update.json
```

In Kleopatra: right-click `aero-update.json`, *Sign/Encrypt*, sign as **Aero**, tick *detached* and
*ASCII armor*, and do **not** tick encrypt.

Then check it with the same code the wallet uses, against the same pinned key, before publishing:

```powershell
core\target\release\aero.exe verify-update dist/aero-update.json dist/aero-update.json.asc
```

That prints two verdicts. `SIGNATURE OK` means every installed copy of Aero will accept the
manifest; `ARCHIVE OK` means the zip sitting next to it is the one the signature actually covers.
Both have to appear. The second exists because the tempting mistake is to sign, then rebuild the zip
for one more small fix: the signature still verifies, and every install then fails on the hash, after
the release page is live. Re-run `ci/release.ps1` and re-sign whenever the archive changes.

> `aero-update.json` is signed byte for byte. Do not open it in an editor and save it: an added
> trailing newline or a BOM is enough to invalidate the signature.

Upload **four** assets to the GitHub release, with these exact names:

| File | What it is |
|---|---|
| `Aero-<version>-Windows-x64-portable.zip` | the release itself |
| `aero-update.json` | signed manifest the updater reads |
| `aero-update.json.asc` | detached signature over it |
| `SHA256SUMS-<version>.txt` | for people verifying by hand |

The release must be marked **Latest** on GitHub: Aero fetches the manifest from
`/releases/latest/download/`, so a release that is not the latest is a release nobody is offered.

## What the in-app updater does with this

`core/src/update.rs`, in order, and it stops at the first thing that does not hold:

1. Fetches `aero-update.json` and `aero-update.json.asc` over Tor.
2. Verifies the detached signature against the pinned key. Nothing in the manifest is parsed until
   this passes.
3. Requires the manifest's version to be **strictly newer** than the running build. A validly signed
   older release is refused: a rollback is an attack, not an update.
4. Downloads the archive and requires its length and SHA-256 to match the signed manifest exactly.
5. Unpacks it to `.aero-update/staged`, refusing any entry that escapes that folder or that names
   `wallets/`, `config/`, `thp-pairing.txt`, `tor/data/`, or any `*.keys`/`*.aero`/`*.plume` file.
6. Moves the old files aside into `.aero-update/old` and moves the new ones in. If any step fails it
   is undone, so a folder is never half one version and half another. The displaced files are
   deleted at the next launch, once the old executable is no longer the one running.

The user is asked before step 4 and told what was signed and by which key. Nothing is downloaded or
installed on its own.

**The first release carrying the updater has to be installed by hand.** Builds before 0.1.28 have no
updater to run, so they cannot be told about it - say so in that release's notes.

## What users do to verify

1. Download the artifact, `SHA256SUMS`, and the signature.
2. Verify the signature with the published public key:
   ```
   minisign -Vm SHA256SUMS -P <AERO_PUBLIC_KEY>
   # or:  gpg --verify SHA256SUMS.asc SHA256SUMS
   ```
3. Verify the artifact hash:
   ```
   sha256sum -c SHA256SUMS        # Linux/macOS
   ```
   On Windows: `Get-FileHash aero_gui.exe -Algorithm SHA256` and compare to the line in
   `SHA256SUMS`.

If both checks pass, the binary is authentic and untampered. If either fails, **do not run it.**

## When an antivirus flags a release

Expect it. Aero is an unsigned binary that starts a second unsigned binary (`tor.exe`), which opens
a local listening socket and then makes outbound connections to a rotating set of addresses around
the world. Described that way and with no publisher attached, it matches how a machine-learning
model has learned to picture a proxy-based malware stager. Defender has flagged releases as
`Trojan:Win32/Bearfoos.A!ml` and `Behavior:Win32/DefenseEvasion.A!ml`.

Read the detection name before doing anything else:

- **`Trojan:...!ml`** is a verdict on the *file*, from a static model. Metadata and build hygiene
  affect it, which is why the executable carries version info, a manifest and ASLR/DEP.
- **`Behavior:...!ml`** is a verdict on what the process *did* at runtime. No amount of file
  polish changes it; the behaviours being scored are the product working as designed.

Neither is cleared by editing code. A model has to be corrected, and only the vendor can do that.

1. **Check the file is really ours first.** A tampered download is a true positive, and reporting it
   as false would ask Microsoft to whitelist an attacker's binary. Compare against `SHA256SUMS`.
2. **Gather the report:**
   ```powershell
   pwsh ci/av-false-positive.ps1 -Detection "Behavior:Win32/DefenseEvasion.A!ml" -Sums dist/SHA256SUMS-<version>.txt
   ```
   It refuses to proceed if a hash does not match, then prints the file details and the text to
   submit at <https://www.microsoft.com/en-us/wdsi/filesubmission> as *Software developer -
   incorrectly detected as malware*. Turnaround is usually a few days and fixes it for every user.
3. **Sign the release.** This is the only durable fix. `ci/release.ps1 -CertPath cert.pfx` signs the
   binaries; an OV certificate accrues reputation over a few weeks, an EV one is trusted at once.
4. **Publish a VirusTotal link** in the release notes so users can see the verdict themselves.

Tell users to install to a stable location such as `%LOCALAPPDATA%\Programs\Aero` rather than the
Desktop or Downloads folder. Defender's cloud reputation weighs where an unknown executable runs
from, and those two directories are where it expects to find something it should worry about.

## Publishing the signing key

- Commit the public key to the repo (e.g. `keys/aero-release.pub`).
- Include the key fingerprint in the release notes and (ideally) a second out-of-band channel.
- Never commit the private key. Keep it offline; sign releases on an air-gapped machine if possible.
