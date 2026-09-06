# SPDX-License-Identifier: BSD-3-Clause
# Gather everything Microsoft asks for when reporting a Defender false positive, and check the
# claim before making it.
#
# Usage:
#   pwsh ci/av-false-positive.ps1 -Detection "Behavior:Win32/DefenseEvasion.A!ml"
#   pwsh ci/av-false-positive.ps1 -Detection "..." -PortableDir dist/aero-portable -Sums dist/SHA256SUMS-0.1.26.txt
#
# A detection ending in "!ml" is a machine-learning verdict, not a signature. No change to the code
# clears it by itself: the model has to be corrected, and only Microsoft can do that. They act on
# these within a few days, and the correction applies to every user at once, which is why submitting
# matters more than anything else in this file.

param(
    [Parameter(Mandatory = $true)][string]$Detection,
    [string]$PortableDir = "dist/aero-portable",
    [string]$Sums = ""
)

$ErrorActionPreference = "Stop"
$portable = Resolve-Path $PortableDir

# The binaries Defender is most likely to name: the app, the core, and Tor itself.
$targets = @("aero_gui.exe", "aero_core.dll", "tor/tor.exe") |
    ForEach-Object { Join-Path $portable $_ } | Where-Object { Test-Path $_ }

Write-Host "=== Files ===`n"
$rows = foreach ($f in $targets) {
    $item = Get-Item -LiteralPath $f
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower()
    $sig = Get-AuthenticodeSignature -LiteralPath $f
    $ver = $item.VersionInfo
    [pscustomobject]@{
        Name      = $item.Name
        Version   = $ver.FileVersion
        Product   = $ver.ProductName
        Signature = $sig.Status
        SHA256    = $hash
    }
}
$rows | Format-List

# Before calling it a false positive, be sure the file is the one that was published. A tampered
# download is a true positive, and reporting it as a false one would ask Microsoft to whitelist it.
if ($Sums) {
    Write-Host "=== Checking against $Sums ===`n"
    $published = @{}
    Get-Content $Sums | ForEach-Object {
        $parts = $_ -split '\s+', 2
        if ($parts.Count -eq 2) { $published[$parts[1].Trim()] = $parts[0].Trim().ToLower() }
    }
    $mismatch = $false
    foreach ($r in $rows) {
        if (-not $published.ContainsKey($r.Name)) {
            Write-Host ("  {0}: not in the checksum file" -f $r.Name)
            continue
        }
        if ($published[$r.Name] -eq $r.SHA256) {
            Write-Host ("  {0}: matches the published build" -f $r.Name)
        } else {
            Write-Warning ("{0}: DOES NOT MATCH the published build" -f $r.Name)
            $mismatch = $true
        }
    }
    if ($mismatch) {
        throw "A binary differs from the published release. Do not report this as a false positive until you know why."
    }
    Write-Host ""
}

$unsigned = $rows | Where-Object { $_.Signature -ne "Valid" }
if ($unsigned) {
    Write-Host "=== Unsigned ===`n"
    Write-Host "  $($unsigned.Name -join ', ')"
    Write-Host "  An unsigned binary has no reputation, and no reputation is most of why the model"
    Write-Host "  guessed the way it did. Signing (ci/release.ps1 -CertPath) is the durable fix;"
    Write-Host "  submitting below is the immediate one.`n"
}

Write-Host "=== Submit ===`n"
Write-Host "  https://www.microsoft.com/en-us/wdsi/filesubmission"
Write-Host "  Choose: 'Software developer' -> 'Incorrectly detected as malware'`n"
Write-Host "  Detection name : $Detection"
Write-Host "  Product        : Aero Wallet, https://github.com/Aero-Developer/aero"
Write-Host "  Attach         : the release .zip (all binaries together, so Tor is judged in context)"
Write-Host @"

  Suggested description:

    Aero is an open-source, Tor-routed Ethereum wallet (BSD-3-Clause).
    Source: https://github.com/Aero-Developer/aero

    The behaviours being scored are the product's stated purpose, not evasion:
      * it starts the bundled tor.exe as a child process, which is how the wallet
        reaches the network at all - there is no non-Tor path,
      * all RPC traffic goes through that local SOCKS proxy on 127.0.0.1,
      * it removes a stale Tor data-directory lock file after an unclean shutdown,
        because Tor refuses to start while one is present.

    The build is reproducible from the tagged source. SHA-256 of the submitted files
    is listed above and published with the release.

"@
Write-Host "  Also upload the zip to https://www.virustotal.com and link the report in the release notes.`n"
