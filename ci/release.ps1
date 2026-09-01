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
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$portable = Resolve-Path $PortableDir
Write-Host "Packaging Aero $Version from $portable"

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
$excluded = @("wallets", "netlog.txt", "obs1_open.png", "aero.exe")
$staging = Join-Path "dist" "aero-release-$Version"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging | Out-Null
Get-ChildItem -LiteralPath $portable |
    Where-Object { $excluded -notcontains $_.Name } |
    ForEach-Object { Copy-Item $_.FullName -Destination $staging -Recurse -Force }

# Belt and braces: refuse to ship if anything secret-shaped survived the copy.
$leaked = Get-ChildItem $staging -Recurse -Include *.keys, *.aero, *.plume -ErrorAction SilentlyContinue
if ($leaked) { throw "refusing to package: wallet files in $staging - $($leaked.Name -join ', ')" }

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

Write-Host "`nNext steps:"
Write-Host "  * Upload $zip + $sumFile to the GitHub release."
Write-Host "  * Upload $zip to https://www.virustotal.com and link the report (proves it's a false positive)."
Write-Host "  * If unsigned + flagged, submit to https://www.microsoft.com/en-us/wdsi/filesubmission"
