# Bootstraps a Windows build environment for Aero's Rust core.
# Mirrors the steps used to build/test this repo on a bare Windows host (no package manager).
#
# Installs:
#   - a portable MinGW-w64 (GCC) toolchain (provides the linker for the GNU Rust target)
#   - the Rust stable GNU toolchain via rustup
#   - cbindgen (for regenerating the C header)
#
# Building the full Qt GUI additionally requires Qt6, CMake >= 3.18 and (optionally) Tor; install
# those separately for your platform (see frontend/INTEGRATION.md).

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dl = "C:\tools\dl"
New-Item -ItemType Directory -Force -Path $dl | Out-Null

# --- MinGW-w64 (linker for x86_64-pc-windows-gnu) ---
if (-not (Test-Path "C:\tools\mingw64\bin\gcc.exe")) {
    Write-Host "Fetching latest WinLibs MinGW-w64..."
    $rel = Invoke-RestMethod "https://api.github.com/repos/brechtsanders/winlibs_mingw/releases/latest" -Headers @{ 'User-Agent' = 'ps' }
    $asset = $rel.assets | Where-Object { $_.name -like '*x86_64*posix*ucrt*.zip' -and $_.name -notlike '*git*' } | Select-Object -First 1
    Invoke-WebRequest $asset.browser_download_url -OutFile "$dl\mingw.zip" -UseBasicParsing
    Expand-Archive "$dl\mingw.zip" -DestinationPath "C:\tools" -Force
}

# --- Rust (GNU toolchain) ---
if (-not (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe")) {
    Write-Host "Installing Rust (stable, x86_64-pc-windows-gnu)..."
    Invoke-WebRequest "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe" -OutFile "$dl\rustup-init.exe" -UseBasicParsing
    & "$dl\rustup-init.exe" -y --default-host x86_64-pc-windows-gnu --profile minimal --default-toolchain stable
}

$env:Path = "C:\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;" + $env:Path

# --- cbindgen ---
if (-not (Test-Path "$env:USERPROFILE\.cargo\bin\cbindgen.exe")) {
    cargo install cbindgen
}

Write-Host "`nToolchain ready. Add this to your PATH for the session:"
Write-Host '  $env:Path = "C:\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;" + $env:Path'
Write-Host "`nThen:  cd core; cargo test"
