# Compute SHA-256 checksums for Aero release artifacts (Windows / PowerShell).
#
#   pwsh scripts/release-checksums.ps1 -Dir dist
#
# Writes <Dir>/SHA256SUMS with "  <hash>  <relative path>" lines, matching the format that
# `sha256sum -c SHA256SUMS` expects, so users can verify a download on any platform.
param([string]$Dir = "dist")

$root = (Resolve-Path $Dir).Path
$lines = Get-ChildItem -Path $root -Recurse -Include *.zip, *.exe, *.dll |
    Sort-Object FullName |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
        $rel = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
        "$hash  $rel"
    }

$out = Join-Path $root "SHA256SUMS"
$lines | Set-Content -Path $out -Encoding ascii
Write-Host "Wrote $out"
$lines
