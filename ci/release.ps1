# SPDX-License-Identifier: BSD-3-Clause
# Aero release helper (Windows). Signs the portable binaries (if a cert is provided), zips the
# portable folder, and writes SHA-256 checksums so users can verify their download.
#
# Usage:
#   pwsh ci/release.ps1 -Version 1.0.0 [-CertPath cert.pfx -CertPassword ****] [-TimestampUrl <url>]
#
# Code-signing is optional but strongly recommended: an unsigned, low-reputation binary that spawns
# tor.exe + opens sockets is exactly what Defender's ML heuristics false-positive (Bearfoos.A!ml).
# An OV cert builds reputation over a few weeks; an EV cert gives instant SmartScreen trust.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$PortableDir = "dist/aero-portable",
    [string]$CertPath = "",
    [string]$CertPassword = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$Notes = ""
)

$ErrorActionPreference = "Stop"
$portable = Resolve-Path $PortableDir
Write-Host "Packaging Aero $Version from $portable"

# 0) The version being packaged has to be the version the built exe claims.
#
# The updater compares the running build's version (compiled in from the CMake project version)
# against the version in the signed manifest. If those two disagree, a release either never offers
# itself or offers itself forever - and it is exactly the kind of mistake that is invisible until it
# is in front of users. Cheaper to refuse here.
$cmakeFile = Join-Path $PSScriptRoot "../frontend/gui/CMakeLists.txt"
if (Test-Path $cmakeFile) {
    $m = Select-String -Path $cmakeFile -Pattern 'project\(aero_gui VERSION ([0-9]+\.[0-9]+\.[0-9]+)' |
        Select-Object -First 1
    if ($m) {
        $cmakeVersion = $m.Matches[0].Groups[1].Value
        if ($cmakeVersion -ne $Version) {
            throw "version mismatch: -Version is $Version but frontend/gui/CMakeLists.txt says $cmakeVersion. Bump the project() line and rebuild, or pass -Version $cmakeVersion."
        }
    }
}

# 1) Sign the executables + libraries (only if a cert was supplied).
$toSign = @("aero_gui.exe", "aero_core.dll", "tor/tor.exe") |
    ForEach-Object { Join-Path $portable $_ } | Where-Object { Test-Path $_ }
if ($CertPath -and (Test-Path $CertPath)) {
    $signtoolCmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtoolCmd) { throw "signtool.exe not found (install the Windows SDK)." }
    $signtool = $signtoolCmd.Source
    foreach ($f in $toSign) {
        Write-Host "Signing $f"
        & $signtool sign /fd sha256 /f $CertPath /p $CertPassword /tr $TimestampUrl /td sha256 $f
        if ($LASTEXITCODE -ne 0) { throw "signing failed for $f" }
    }
} else {
    Write-Warning "No -CertPath given: shipping UNSIGNED (expect SmartScreen/Defender warnings). See notes at top."
}

# 2) Zip the portable folder - from a staging copy, never the folder itself.
#
# A portable folder that has ever been run is also somebody's wallet: Aero keeps `wallets/` right
# next to the exe, which is the whole point of portable mode. Zipping it directly would publish
# those key files to a release page, so the excluded names below are load-bearing, not tidiness.
# Local state (a netlog, a screenshot) is dropped for the same reason: it is the developer's, not
# the user's.
#
# These names are the same ones `core/src/update.rs` refuses to install over. The two lists exist for
# opposite reasons - this one stops the developer publishing private state, that one stops an archive
# overwriting the user's - and they have to agree, or a release packages fine and then refuses to
# install.
$excluded = @(
    "wallets",         # encrypted keystores
    "config",          # QSettings: nodes, pins, privacy choices
    "thp-pairing.txt", # Trezor pairing credential
    "netlog.txt",
    ".aero-update",    # staged/backed-up files from a previous in-place update
    "obs1_open.png",
    "aero.exe")
# Nested state, stripped after the copy because it lives inside a folder that does ship. `tor/data`
# is the developer's Tor identity: guard selection, bandwidth history, `keys/`, and forty megabytes
# of consensus cache the user's own Tor would fetch anyway.
$excludedNested = @("tor/data")
$staging = Join-Path "dist" "aero-release-$Version"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging | Out-Null
Get-ChildItem -LiteralPath $portable -Force |
    Where-Object { $excluded -notcontains $_.Name } |
    ForEach-Object { Copy-Item $_.FullName -Destination $staging -Recurse -Force }
foreach ($rel in $excludedNested) {
    $p = Join-Path $staging ($rel -replace '/', '\')
    if (Test-Path $p) {
        Write-Host "Stripping $rel (local Tor state, not part of the release)"
        Remove-Item $p -Recurse -Force
    }
}

# Belt and braces: refuse to ship if anything the updater would reject survived the copy. Without
# this the mistake is silent until an update fails on a user's machine - and by then the archive is
# published, hashed and signed.
$leaked = Get-ChildItem $staging -Recurse -Force -Include *.keys, *.aero, *.plume -ErrorAction SilentlyContinue
if ($leaked) { throw "refusing to package: wallet files in $staging - $($leaked.Name -join ', ')" }
foreach ($name in ($excluded + $excludedNested)) {
    $p = Join-Path $staging ($name -replace '/', '\')
    if (Test-Path $p) { throw "refusing to package: $name survived into $staging" }
}

$zip = "dist/Aero-$Version-Windows-x64-portable.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip
Write-Host "Wrote $zip"

# 3) SHA-256 checksums for the zip + the key binaries (publish these on the release page).
$checkTargets = @($zip) + $toSign
$sums = foreach ($f in $checkTargets) {
    $item = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLower()
    "{0}  {1}" -f $h, $item.Name
}
$sumFile = "dist/SHA256SUMS-$Version.txt"
$sums | Set-Content -Encoding ascii $sumFile
Write-Host "`nSHA-256 checksums ($sumFile):"
$sums | ForEach-Object { Write-Host "  $_" }

# 4) The update manifest: the one file the release key signs.
#
# Everything the updater trusts comes from here. The signature covers these exact bytes, and these
# bytes name the archive and its hash, so signing this one small file is what authorises the whole
# release. Nothing else needs a signature - and nothing else gets one, because a second signed thing
# is a second thing to remember, and the one that gets forgotten is the one that matters.
#
# Written as UTF-8 with no BOM and no trailing newline: the signature is over bytes, so the file that
# is uploaded must be byte-for-byte the file that was signed. Do not open it in an editor and save.
$zipItem = Get-Item -LiteralPath $zip
$manifest = [ordered]@{
    version = $Version
    file    = $zipItem.Name
    sha256  = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipItem.FullName).Hash.ToLower()
    size    = $zipItem.Length
    notes   = $Notes
}
$manifestPath = "dist/aero-update.json"
$json = $manifest | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText(
    (Join-Path (Get-Location) $manifestPath),
    $json,
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $manifestPath"
Write-Host "  $json"

Write-Host "`nNext steps:"
Write-Host "  1. Sign the manifest with the Aero release key (fingerprint FD06 516B 6C76 2BB8 B016  16DE 80D5 05C2 5B02 54B3):"
Write-Host "         gpg --local-user FD06516B6C762BB8B01616DE80D505C25B0254B3 --armor --detach-sign --output dist/aero-update.json.asc dist/aero-update.json"
Write-Host "     (Kleopatra: right-click aero-update.json -> Sign/Encrypt -> Sign as Aero, detached, ASCII armor.)"
Write-Host "  2. Verify it before publishing:"
Write-Host "         gpg --verify dist/aero-update.json.asc dist/aero-update.json"
Write-Host "  3. Upload ALL FOUR to the GitHub release, as release assets with these exact names:"
Write-Host "         $zip"
Write-Host "         $sumFile"
Write-Host "         $manifestPath"
Write-Host "         $manifestPath.asc"
Write-Host "     Aero fetches aero-update.json(.asc) from /releases/latest/download/, so the release must be marked 'latest'."
Write-Host "  * Upload $zip to https://www.virustotal.com and link the report (proves it's a false positive)."
Write-Host "  * If unsigned + flagged, submit to https://www.microsoft.com/en-us/wdsi/filesubmission"
