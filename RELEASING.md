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

Sign the checksum file (not each artifact) with the project key. Either tool is fine; publish the
public key in the repo and the release notes.

**minisign** (recommended - small, no keyring):

```powershell
minisign -Sm dist/SHA256SUMS          # produces dist/SHA256SUMS.minisig
```

**GPG**:

```powershell
gpg --armor --detach-sign dist/SHA256SUMS   # produces dist/SHA256SUMS.asc
```

Upload `SHA256SUMS` and its `.minisig`/`.asc` alongside the release artifacts.

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

## Publishing the signing key

- Commit the public key to the repo (e.g. `keys/aero-release.pub`).
- Include the key fingerprint in the release notes and (ideally) a second out-of-band channel.
- Never commit the private key. Keep it offline; sign releases on an air-gapped machine if possible.
