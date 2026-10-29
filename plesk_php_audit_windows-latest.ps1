# plesk_php_audit_windows.ps1  (v3)
# v3: domain status uses only Plesk website PHP builds (panel PHP no longer causes false "unsupported");
#     counts only domains with PHP switched on.
# Read-only PHP audit for Plesk for Windows (shared or dedicated). Changes nothing.
#
# Usage (elevated PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\plesk_php_audit_windows.ps1                # readable report
#   powershell -ExecutionPolicy Bypass -File .\plesk_php_audit_windows.ps1 -Csv           # one CSV row for this server
#   powershell -ExecutionPolicy Bypass -File .\plesk_php_audit_windows.ps1 -CsvHeader     # the CSV header row only
#   powershell -ExecutionPolicy Bypass -File .\plesk_php_audit_windows.ps1 -ListDomains   # report + domain names (migration work)
#
# Windows rules (PHP2Shell, CVE-2026-109618 / CVE-2026-109619):
#  - Fixed builds carry new version numbers: 8.2.35, 8.3.36, 8.4.27, 8.5.12
#  - No fixed Windows builds exist for PHP 8.1 or older -> unsupported, move sites to 8.2+
#  - Panel PHP (plesk-engine) is fixed in Plesk 18.0.80 #11 / 18.0.81 #4 and later (PHP 8.4.27)
# Domain counts: unsupported = below 8.2 or on an unpatched build (move now); supported = 8.2+ patched.
# Update $Fixed when a new advisory lists newer builds.
# Exit code = number of problems found (0 = compliant).

param([switch]$Csv, [switch]$CsvHeader, [switch]$ListDomains)

$Header = 'hostname,os,plesk_version,audit_date_utc,cutoff,php_builds_total,php_builds_not_patched,not_patched_versions,panel_php,domains_with_php,domains_unsupported,domains_stopgap,domains_supported,unsupported_breakdown,stale_php_processes,result'
if ($CsvHeader) { Write-Output $Header; exit 0 }
if ($Csv) { $ListDomains = $false }

$Fixed = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
$PanelMin = '8.4.27'

$PleskDir = $env:plesk_dir
if (-not $PleskDir) { $PleskDir = 'C:\Program Files (x86)\Plesk\' }
$script:Fails = 0; $script:Builds = 0; $script:BuildsBad = 0; $script:BadList = @(); $script:Panel = 'n/a'
$BadMM = @{}

function Say([string]$Text, [string]$Color) {
    if ($Csv) { return }
    if ($Color) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}

function Get-PhpVersion([string]$Exe) {
    try { $line = (& $Exe -v 2>$null | Select-Object -First 1) } catch { return $null }
    if ($line -match 'PHP (\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
}

function Get-Verdict([string]$Ver, [string]$MinOverride) {
    if (-not $Ver) { return 'NOT PATCHED (unknown version)' }
    $v  = [version]$Ver
    $mm = "$($v.Major).$($v.Minor)"
    if ($MinOverride) {
        if ($v -ge [version]$MinOverride) { return 'PATCHED' } else { return "NOT PATCHED (needs $MinOverride+)" }
    }
    if ($v -lt [version]'8.2') { return 'NOT PATCHED (no Windows fix - move to 8.2+)' }
    if (-not $Fixed.ContainsKey($mm)) { return 'CHECK (version not in fixed list - verify advisory)' }
    if ($v -ge [version]$Fixed[$mm]) { return 'PATCHED' }
    return "NOT PATCHED (needs $($Fixed[$mm]))"
}

function Show-Binary([string]$Label, [string]$Exe, [string]$MinOverride, [string]$Tag, [switch]$Site) {
    if (-not (Test-Path $Exe)) { return $null }
    $ver = Get-PhpVersion $Exe
    $verdict = Get-Verdict $ver $MinOverride
    $color = if ($verdict -eq 'PATCHED') { 'Green' } elseif ($verdict -like 'CHECK*') { 'Yellow' } else { 'Red' }
    $built = (Get-Item $Exe).LastWriteTime.ToString('yyyy-MM-dd')
    $shown = if ($ver) { $ver } else { 'unknown' }
    Say ('{0,-48} {1,-20} {2,-9} file date {3}' -f $verdict, $Label, $shown, $built) $color
    $script:Builds++
    if ($verdict -ne 'PATCHED') {
        $script:Fails++; $script:BuildsBad++; $script:BadList += $Tag
        # Only Plesk website PHP builds decide a domain's status; the panel's PHP must not.
        if ($Site -and $ver) { $v = [version]$ver; $BadMM["$($v.Major).$($v.Minor)"] = $verdict }
    }
    return $verdict
}

$os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Windows' }
$pleskVer = 'unknown'
try { $l = (& plesk version 2>$null | Select-String -Pattern 'Product version' | Select-Object -First 1).Line; if ($l) { $pleskVer = ($l -split ':\s*', 2)[1].Trim() } } catch {}

Say "== $env:COMPUTERNAME   $os   $(Get-Date -Format 'yyyy-MM-dd HH:mm')   Plesk: $pleskVer"

Say "`n== Plesk website PHP"
$addl = Join-Path $PleskDir 'Additional'
Get-ChildItem -Path $addl -Directory -Filter 'PleskPHP*' -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
    [void](Show-Binary $_.Name (Join-Path $_.FullName 'php.exe') $null $_.Name -Site)
}

Say "`n== Plesk panel PHP (plesk-engine) - patched only by upgrading the Plesk release"
$pv = Show-Binary 'panel PHP' (Join-Path $PleskDir 'admin\bin\php.exe') $PanelMin 'panel'
if ($pv) { $script:Panel = $pv }

# ---- Domain counts ----
$dTotal = 0; $dUnsup = 0; $dSup = 0; $unsupBy = @{}; $names = @()
try {
    $q = "SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id=d.id"
    # Only domains with PHP switched on; fall back to all hosted domains if this Plesk schema lacks the column.
    $rows = & plesk db -Ne "$q WHERE h.php='true' ORDER BY d.name" 2>$null
    if ($LASTEXITCODE -ne 0) {
        $rows = & plesk db -Ne "$q ORDER BY d.name" 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'db query failed' }
    }
    foreach ($row in $rows) {
        $parts = $row -split "`t"
        if ($parts.Count -lt 2) { continue }
        $dom = $parts[0]; $handler = $parts[1]
        $mm = $null
        if ($handler -match '(\d)\.(\d{1,2})') { $mm = "$($Matches[1]).$($Matches[2])" }
        elseif ($handler -match 'php(\d)(\d{1,2})') { $mm = "$($Matches[1]).$($Matches[2])" }
        if (-not $mm) { continue }
        $dTotal++
        if (([version]$mm -lt [version]'8.2') -or $BadMM.ContainsKey($mm)) {
            $dUnsup++; $unsupBy[$mm] = 1 + [int]$unsupBy[$mm]
            if ($ListDomains) { $names += "  $dom  ($handler)" }
        } else { $dSup++ }
    }
} catch {
    $dTotal = 'error'; $dUnsup = 'error'; $dSup = 'error'; $script:Fails++
    Say '  Could not query the Plesk database. Check Tools & Settings > PHP Settings (usage per version).' 'Yellow'
}
$breakdown = ($unsupBy.Keys | Sort-Object { [version]$_ } | ForEach-Object { "PHP$_=$($unsupBy[$_])" }) -join ' '
if ($dUnsup -is [int]) { $script:Fails += $dUnsup }

Say "`n== Domains by PHP status"
Say ('  {0,-36} {1}' -f 'Domains with PHP', $dTotal)
Say ('  {0,-36} {1}{2}' -f 'Unsupported (move now)', $dUnsup, $(if ($breakdown) { "   [$breakdown]" } else { '' }))
Say ('  {0,-36} {1}' -f 'Supported 8.2+', $dSup)
if ($ListDomains -and $names.Count -gt 0) { Say '  Unsupported domains:'; $names | ForEach-Object { Say $_ } }

# ---- Stale processes ----
$stale = @(Get-Process -Name 'php-cgi', 'php' -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and (Test-Path $_.Path) -and $_.StartTime -lt (Get-Item $_.Path).LastWriteTime
})
Say "`n== PHP processes started before their php binary was replaced: $($stale.Count)"
if ($stale.Count -gt 0) {
    Say '  -> recycle the IIS application pools (or run iisreset in a maintenance window)'
    $script:Fails++
}

$result = if ($script:Fails -eq 0) { 'OK' } else { 'ACTION REQUIRED' }
Say ''
if ($result -eq 'OK') { Say 'RESULT: OK' 'Green' } else { Say "RESULT: ACTION REQUIRED - $($script:Fails) problem(s). Follow the SOP." 'Red' }
Say 'Note: checks versions, not exploitability. Confirm fixed builds in the Plesk advisory.'

if ($Csv) {
    function Q([string]$s) { '"' + ($s -replace '"', '""') + '"' }
    $fields = @(
        (Q $env:COMPUTERNAME), (Q $os), (Q $pleskVer), (Q (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')), (Q 'version-based'),
        $script:Builds, $script:BuildsBad, (Q ($script:BadList -join ' ')), (Q $script:Panel),
        $dTotal, $dUnsup, 0, $dSup, (Q $breakdown), $stale.Count, (Q $result)
    )
    Write-Output ($fields -join ',')
}
exit $script:Fails
