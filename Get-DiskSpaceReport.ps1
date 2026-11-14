#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only disk space report. Run elevated for the full picture.
.DESCRIPTION
    Combines the audits from this repo's modules with system-level checks that need elevation:
    Windows upgrade leftovers, hibernation/page files, System Restore storage, reserved storage,
    the search index, older third-party driver-store packages, orphaned Windows Installer files,
    old .NET SDKs, and a single-pass scan of the largest folders and files on the system drive.

    Deletes nothing. Every row says what it is and how to reclaim it.
.PARAMETER SkipFolderScan
    Skip the full scan of the system drive (the slowest part, usually a few minutes).
.PARAMETER SkipModuleAudits
    Skip the RoutineDiskCleanup and NvidiaUpdateCleaner audits (the DISM analysis inside them takes a few minutes).
.PARAMETER BigFileGB
    Files at least this large are listed individually. Default 1 GB.
.PARAMETER OutFile
    Where to save the text report. Defaults to %LOCALAPPDATA%\RoutineDiskCleanup\reports.
.EXAMPLE
    # From an elevated PowerShell
    .\Get-DiskSpaceReport.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipFolderScan,
    [switch]$SkipModuleAudits,
    [double]$BigFileGB = 1,
    [string]$OutFile = (Join-Path $env:LOCALAPPDATA ("RoutineDiskCleanup\reports\DiskSpaceReport-{0:yyyyMMdd-HHmm}.txt" -f (Get-Date)))
)

$ErrorActionPreference = 'Continue'
$sys = $env:SystemDrive
$windir = $env:SystemRoot
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Write-Warning 'Not elevated: system locations will be undercounted or skipped. Re-run from an elevated PowerShell for the full report.' }

# ------------------------------------------------------------------
# Fast single-pass scanner. Skips reparse-point folders (junctions, symlinks) and
# cloud-only placeholder files, which report a size but use no local disk.
# ------------------------------------------------------------------
if (-not ('DiskSpaceReport.Scanner' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
namespace DiskSpaceReport {
    public class ScanResult {
        public long Bytes; public long Files;
        public Dictionary<string, long> Buckets = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        public List<KeyValuePair<string, long>> BigFiles = new List<KeyValuePair<string, long>>();
    }
    public static class Scanner {
        const FileAttributes CloudOnly = (FileAttributes)0x1000 | (FileAttributes)0x40000 | (FileAttributes)0x400000;
        // Size of a folder tree. Any folder in 'watch' gets each of its child folders reported as a bucket.
        public static ScanResult Scan(string root, string[] watch, long bigThreshold) {
            var r = new ScanResult();
            var watchSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (watch != null) foreach (var w in watch) watchSet.Add(w.TrimEnd('\\'));
            var stack = new Stack<KeyValuePair<DirectoryInfo, string[]>>();
            stack.Push(new KeyValuePair<DirectoryInfo, string[]>(new DirectoryInfo(root), new string[0]));
            while (stack.Count > 0) {
                var e = stack.Pop(); var dir = e.Key; var keys = e.Value;
                bool watched = watchSet.Contains(dir.FullName.TrimEnd('\\'));
                FileSystemInfo[] items;
                try { items = dir.GetFileSystemInfos(); } catch { continue; }
                foreach (var it in items) {
                    var d = it as DirectoryInfo;
                    if (d != null) {
                        if ((d.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        var k = keys;
                        if (watched) { k = new string[keys.Length + 1]; keys.CopyTo(k, 0); k[keys.Length] = d.FullName; }
                        stack.Push(new KeyValuePair<DirectoryInfo, string[]>(d, k));
                        continue;
                    }
                    var f = (FileInfo)it;
                    if ((f.Attributes & CloudOnly) != 0) continue;
                    long len; try { len = f.Length; } catch { continue; }
                    r.Bytes += len; r.Files++;
                    foreach (var k in keys) { long v; r.Buckets.TryGetValue(k, out v); r.Buckets[k] = v + len; }
                    if (watched) { long v; r.Buckets.TryGetValue(f.FullName, out v); r.Buckets[f.FullName] = v + len; }
                    if (len >= bigThreshold) r.BigFiles.Add(new KeyValuePair<string, long>(f.FullName, len));
                }
            }
            return r;
        }
    }
}
'@
}

function Get-TreeBytes([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $null }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and -not $item.PSIsContainer) { return [long]$item.Length }
    return [DiskSpaceReport.Scanner]::Scan($Path, $null, [long]::MaxValue).Bytes
}

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($Area, $Item, $Bytes, $Action) {
    if ($null -eq $Bytes) { return }
    $rows.Add([PSCustomObject]@{ Area = $Area; Item = $Item; SizeGB = [math]::Round($Bytes / 1GB, 2); Action = $Action })
}
function Step($msg) { Write-Host "-> $msg" -ForegroundColor Cyan }

# ------------------------------------------------------------------
# 1. Windows system items
# ------------------------------------------------------------------
Step 'Windows upgrade leftovers, system files, restore points'
Add-Row 'Windows' "$sys\Windows.old" (Get-TreeBytes "$sys\Windows.old") 'Previous Windows install. Disk Cleanup (cleanmgr) > Clean up system files > "Previous Windows installation(s)". Removes the option to roll back.'
foreach ($d in '$Windows.~BT', '$Windows.~WS', '$GetCurrent', 'ESD') {
    Add-Row 'Windows' "$sys\$d" (Get-TreeBytes "$sys\$d") 'Feature-upgrade staging files. Safe once no upgrade is in progress; cleanmgr "Temporary Windows installation files".'
}
Add-Row 'Windows' "$windir\MEMORY.DMP" (Get-TreeBytes "$windir\MEMORY.DMP") 'Full kernel crash dump from the last blue screen. Safe to delete unless you are debugging it.'
Add-Row 'Windows' "$sys\hiberfil.sys" (Get-TreeBytes "$sys\hiberfil.sys") 'Hibernation file. "powercfg /h off" removes it (also disables Fast Startup); "powercfg /h /type reduced" roughly halves it and keeps Fast Startup.'
Add-Row 'Windows' "$sys\pagefile.sys" (Get-TreeBytes "$sys\pagefile.sys") 'Page file. Leave system-managed unless you know your workload; shown for context.'
Add-Row 'Windows' "$sys\swapfile.sys" (Get-TreeBytes "$sys\swapfile.sys") 'Store-app swap file, managed with the page file. Shown for context.'

try {
    $vol = Get-CimInstance Win32_Volume -Filter "DriveLetter='$sys'" -ErrorAction Stop
    $ss = Get-CimInstance Win32_ShadowStorage -ErrorAction Stop | Where-Object { $_.Volume -like "*$($vol.DeviceID.Replace('\','\\'))*" -or $_.Volume.ToString() -like "*$($vol.DeviceID)*" }
    foreach ($s in $ss) {
        Add-Row 'Windows' 'System Restore / shadow copies (used)' ([long]$s.UsedSpace) ("Restore points. Max allowed: {0:N1} GB. Cap with 'vssadmin resize shadowstorage /for={1} /on={1} /maxsize=5%', or delete all but the newest via cleanmgr > More Options." -f ($s.MaxSpace / 1GB), $sys)
    }
} catch { if ($elevated) { Write-Warning "Shadow storage query failed: $($_.Exception.Message)" } }

try {
    $rs = Get-WindowsReservedStorageState -ErrorAction Stop
    if ($rs.ReservedStorageState -eq 'Enabled') {
        $rows.Add([PSCustomObject]@{ Area = 'Windows'; Item = 'Reserved storage'; SizeGB = $null; Action = 'Enabled (typically ~7 GB). "Set-WindowsReservedStorageState -State Disabled" frees it, but updates then need that space free themselves. Usually leave on.' })
    }
} catch { }

Add-Row 'Windows' 'Search index' (Get-TreeBytes "$env:ProgramData\Microsoft\Search\Data") 'Windows Search database. If huge, rebuild it: Indexing Options > Advanced > Rebuild, or trim indexed locations.'
Add-Row 'Windows' 'Defender scan history' (Get-TreeBytes "$env:ProgramData\Microsoft\Windows Defender\Scans\History") 'Defender keeps this trimmed itself; only notable if it is large.'
Add-Row 'Windows' 'Windows logs (Logs, LogFiles, winevt)' ((Get-TreeBytes "$windir\Logs") + (Get-TreeBytes "$windir\System32\LogFiles") + (Get-TreeBytes "$windir\System32\winevt\Logs")) 'Usually small. Large CBS logs can be deleted; event logs are capped per log in Event Viewer.'

# ------------------------------------------------------------------
# 2. Windows Installer cache: total, and files no installed product or patch references
# ------------------------------------------------------------------
Step 'Windows Installer cache'
$installerDir = Join-Path $windir 'Installer'
Add-Row 'Installer' "$installerDir (total)" (Get-TreeBytes $installerDir) 'Needed to repair, update and uninstall MSI apps. Never delete wholesale.'
try {
    $msi = New-Object -ComObject WindowsInstaller.Installer
    $referenced = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # 's-1-1-0' (everyone) covers every account's per-user installs but needs elevation;
    # '' covers the machine plus the current user only.
    $allUsers = $true
    try { $products = @($msi.ProductsEx('', 's-1-1-0', 7)); $patches = @($msi.PatchesEx('', 's-1-1-0', 7, 15)) }
    catch { $allUsers = $false; $products = @($msi.ProductsEx('', '', 7)); $patches = @($msi.PatchesEx('', '', 7, 15)) }
    foreach ($p in $products) { try { $lp = $p.InstallProperty('LocalPackage'); if ($lp) { [void]$referenced.Add($lp) } } catch { } }
    foreach ($p in $patches) { try { $lp = $p.PatchProperty('LocalPackage'); if ($lp) { [void]$referenced.Add($lp) } } catch { } }
    # Only trust the orphan list when every account's installs were checked
    if ($referenced.Count -gt 0 -and $allUsers) {
        $orphans = @(Get-ChildItem -LiteralPath $installerDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.msi', '.msp' -and -not $referenced.Contains($_.FullName) })
        if ($orphans.Count -gt 0) {
            Add-Row 'Installer' ("Orphaned .msi/.msp in Installer ({0} files)" -f $orphans.Count) (($orphans | Measure-Object Length -Sum).Sum) 'Not referenced by any installed product or patch. Lower-risk to reclaim, but MOVE them to another drive for a month rather than deleting.'
        }
    }
} catch { Write-Warning "Could not enumerate Windows Installer products: $($_.Exception.Message)" }
Add-Row 'Installer' "$env:ProgramData\Package Cache" (Get-TreeBytes "$env:ProgramData\Package Cache") 'Bundle installers (Visual Studio, .NET, VC++ runtimes). Needed for repair/uninstall; do not delete by hand. Shrinks when the owning apps are uninstalled.'

# ------------------------------------------------------------------
# 3. Driver store: older versions of third-party drivers
# ------------------------------------------------------------------
Step 'Driver store'
if ($elevated) {
    try {
        $drivers = Get-WindowsDriver -Online -ErrorAction Stop
        $groups = $drivers | Group-Object { '{0}|{1}' -f $_.ProviderName, (Split-Path $_.OriginalFileName -Leaf) } | Where-Object Count -gt 1
        foreach ($g in $groups) {
            $sorted = $g.Group | Sort-Object { try { [version]$_.Version } catch { [version]'0.0' } }, Date -Descending
            $older = $sorted | Select-Object -Skip 1
            $bytes = [long]0
            foreach ($d in $older) { $bytes += [long](Get-TreeBytes (Split-Path $d.OriginalFileName -Parent)) }
            if ($bytes -lt 50MB) { continue }
            $provider = $g.Group[0].ProviderName
            $names = ($older | ForEach-Object Driver) -join ', '
            $how = "pnputil /delete-driver <oemNN.inf> (no /force, so Windows refuses anything in use): $names"
            if ($provider -match 'NVIDIA') { $how = 'Covered by NvidiaUpdateCleaner: Remove-NvidiaDriverStorePackage. ' + $names }
            Add-Row 'DriverStore' ("{0} {1}: {2} older version(s), newest {3}" -f $provider, (Split-Path $g.Group[0].OriginalFileName -Leaf), @($older).Count, $sorted[0].Version) $bytes $how
        }
    } catch { Write-Warning "Driver store query failed: $($_.Exception.Message)" }
} else {
    Write-Warning 'Skipping driver store analysis (needs elevation).'
}

# ------------------------------------------------------------------
# 4. Developer runtimes, WSL / Docker disks
# ------------------------------------------------------------------
Step 'Developer runtimes and virtual disks'
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnet) {
    foreach ($line in (& $dotnet.Source --list-sdks 2>$null)) {
        if ($line -match '^(\S+)\s+\[(.+)\]$') {
            $ver = $Matches[1]; $dir = Join-Path $Matches[2] $ver
            $major = [int]($ver.Split('.')[0])
            $note = 'Uninstall from Apps & features if no project needs it.'
            if ($major -lt 8) { $note = 'Long out of support. ' + $note }
            Add-Row 'Dev' ".NET SDK $ver" (Get-TreeBytes $dir) $note
        }
    }
}
$vhdRoots = @("$env:LOCALAPPDATA\Packages", "$env:LOCALAPPDATA\Docker", "$env:LOCALAPPDATA\wsl", "$env:ProgramData\DockerDesktop")
foreach ($root in $vhdRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root -Recurse -Force -Filter *.vhdx -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Row 'Dev' "Virtual disk $($_.FullName)" $_.Length 'WSL/Docker disks never shrink on their own. Inside: prune images/files. Then "wsl --shutdown" and "Optimize-VHD -Mode Full" (Hyper-V) or diskpart "compact vdisk".'
    }
}

# ------------------------------------------------------------------
# 5. Installed Steam games with last-played dates (usually the biggest lever on a gaming PC)
# ------------------------------------------------------------------
Step 'Steam libraries'
$games = @()
$steamRoot = $null
try { $steamRoot = ((Get-ItemProperty 'HKCU:\Software\Valve\Steam' -ErrorAction Stop).SteamPath) -replace '/', '\' } catch { }
if ($steamRoot -and (Test-Path -LiteralPath $steamRoot)) {
    # libraryfolders.vdf lists each library and the app IDs Steam considers installed in it.
    # A manifest on disk that its library doesn't list is a copy Steam no longer tracks.
    $registered = @{}
    $vdf = Join-Path $steamRoot 'steamapps\libraryfolders.vdf'
    if (Test-Path -LiteralPath $vdf) {
        $vdfText = Get-Content -LiteralPath $vdf -Raw
        foreach ($b in [regex]::Matches($vdfText, '"path"\s+"([^"]+)"[\s\S]*?"apps"\s*\{([^}]*)\}')) {
            $libPath = ($b.Groups[1].Value -replace '\\\\', '\').TrimEnd('\')
            $registered[$libPath] = @([regex]::Matches($b.Groups[2].Value, '"(\d+)"\s+"\d+"') | ForEach-Object { $_.Groups[1].Value })
        }
    }
    if ($registered.Count -eq 0) { $registered[$steamRoot.TrimEnd('\')] = $null }
    $epoch = [datetime]'1970-01-01Z'
    foreach ($lib in $registered.Keys) {
        foreach ($acf in (Get-ChildItem -LiteralPath (Join-Path $lib 'steamapps') -Filter 'appmanifest_*.acf' -ErrorAction SilentlyContinue)) {
            $t = Get-Content -LiteralPath $acf.FullName -Raw
            $get = { param($k) if ($t -match "`"$k`"\s+`"([^`"]*)`"") { $Matches[1] } }
            $appId = & $get 'appid'
            $installDir = Join-Path $lib ('steamapps\common\' + (& $get 'installdir'))
            $isRegistered = ($null -eq $registered[$lib]) -or ($appId -in $registered[$lib])
            # Trust the manifest's size for tracked games; measure untracked leftovers, which may be partial
            $size = if ($isRegistered) { [long](& $get 'SizeOnDisk') } else { [long](Get-TreeBytes $installDir) }
            $lp = [long](& $get 'LastPlayed')
            $last = if ($lp -gt 0) { $epoch.AddSeconds($lp).ToLocalTime() } else { $null }
            $games += [PSCustomObject]@{
                SizeGB     = [math]::Round($size / 1GB, 2)
                LastPlayed = if ($last) { $last.ToString('yyyy-MM-dd') } else { 'never' }
                DaysAgo    = if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null }
                Drive      = $lib.Substring(0, 2).ToUpper()
                Tracked    = $isRegistered
                Name       = & $get 'name'
                AppId      = $appId
                Folder     = $installDir
                Manifest   = $acf.FullName
            }
        }
        $ws = Join-Path $lib 'steamapps\workshop'
        Add-Row 'Games' "Steam Workshop content ($lib)" (Get-TreeBytes $ws) 'Mods/downloads for subscribed items. Unsubscribe in the game''s Workshop page to free it.'
    }
    foreach ($g in ($games | Where-Object { -not $_.Tracked -and $_.SizeGB -gt 0 })) {
        $dup = @($games | Where-Object { $_.Tracked -and $_.AppId -eq $g.AppId })
        $why = if ($dup) { "Steam tracks the copy on $($dup[0].Drive) instead" } else { 'not installed in any Steam library' }
        Add-Row 'Games' "Untracked Steam copy: $($g.Name) on $($g.Drive)" ([long]($g.SizeGB * 1GB)) "Leftover Steam no longer manages ($why). With Steam closed, delete '$($g.Folder)' and '$($g.Manifest)'."
    }
    $stale = @($games | Where-Object { $_.Tracked -and $_.Drive -eq $sys.ToUpper() -and ($null -eq $_.DaysAgo -or $_.DaysAgo -ge 180) })
    if ($stale.Count -gt 0) {
        Add-Row 'Games' ("{0} Steam games on {1} not played in 6+ months" -f $stale.Count, $sys) ([long](($stale | Measure-Object SizeGB -Sum).Sum * 1GB)) 'See the Steam games table below. Uninstall in Steam, or Steam > Settings > Storage > move them to another library drive.'
    }
}

# ------------------------------------------------------------------
# 6. This repo's module audits (they measure system locations properly when elevated)
# ------------------------------------------------------------------
if (-not $SkipModuleAudits) {
    $rdc = Join-Path $PSScriptRoot 'RoutineDiskCleanup\RoutineDiskCleanup.psd1'
    if (Test-Path -LiteralPath $rdc) {
        Step 'RoutineDiskCleanup audit (all categories; DISM analysis takes a few minutes)'
        Import-Module $rdc -Force
        foreach ($i in (Get-RoutineDiskCleanupInfo -IncludeAll -AllUsers:$elevated)) {
            $how = "Invoke-RoutineDiskCleanup -Category $($i.Category)"
            if ($i.User -and $i.User -ne '(system)' -and $i.User -ne $env:USERNAME) { $how += ' -AllUsers' }
            Add-Row "RDC:$($i.Category)" $i.Path ([long]($i.SizeMB * 1MB)) $how
        }
    }
    $nuc = Join-Path $PSScriptRoot 'NvidiaUpdateCleaner\NvidiaUpdateCleaner.psd1'
    if ((Test-Path -LiteralPath $nuc) -and (Test-Path "$env:ProgramFiles\NVIDIA Corporation")) {
        Step 'NvidiaUpdateCleaner audit'
        Import-Module $nuc -Force
        foreach ($i in (Get-NvidiaUpdateCleanupInfo -IncludeShaderCache -IncludeDriverStore)) {
            Add-Row "NVIDIA:$($i.Category)" $i.Path ([long]($i.SizeMB * 1MB)) 'Get-NvidiaUpdateCleanupInfo -IncludeShaderCache -IncludeDriverStore | Remove-NvidiaUpdateCleanupItem'
        }
    }
}

# ------------------------------------------------------------------
# 7. Where the space actually is: one pass over the system drive
# ------------------------------------------------------------------
$topFolders = @(); $bigFiles = @(); $scan = $null
if (-not $SkipFolderScan) {
    Step "Scanning $sys\ (one pass; a few minutes on a full drive)"
    $watch = @("$sys\", "$env:ProgramData", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$sys\Users")
    # Break down every account's profile, not just the one running the report (other profiles need elevation)
    foreach ($prof in (Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.LocalPath })) {
        $watch += $prof.LocalPath, (Join-Path $prof.LocalPath 'AppData\Local'), (Join-Path $prof.LocalPath 'AppData\Roaming')
    }
    $watch = $watch | Where-Object { $_ } | Sort-Object -Unique
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $scan = [DiskSpaceReport.Scanner]::Scan("$sys\", [string[]]$watch, [long]($BigFileGB * 1GB))
    Write-Host ("   scanned {0:N0} files, {1:N1} GB in {2:N0}s" -f $scan.Files, ($scan.Bytes / 1GB), $sw.Elapsed.TotalSeconds)
    $topFolders = $scan.Buckets.GetEnumerator() | Where-Object { $_.Value -ge 500MB } | Sort-Object Value -Descending | Select-Object -First 40 |
        ForEach-Object { [PSCustomObject]@{ SizeGB = [math]::Round($_.Value / 1GB, 2); Path = $_.Key } }
    $bigFiles = $scan.BigFiles | Sort-Object Value -Descending | Select-Object -First 30 |
        ForEach-Object { [PSCustomObject]@{ SizeGB = [math]::Round($_.Value / 1GB, 2); Modified = (Get-Item -LiteralPath $_.Key -Force -ErrorAction SilentlyContinue).LastWriteTime.ToString('yyyy-MM-dd'); Path = $_.Key } }
}

# ------------------------------------------------------------------
# Output
# ------------------------------------------------------------------
$v = Get-Volume -DriveLetter $sys[0]
$header = @(
    "Disk space report  $(Get-Date -Format 'yyyy-MM-dd HH:mm')  elevated=$elevated"
    ("{0} {1:N1} GB free of {2:N1} GB ({3:P0} used)" -f $sys, ($v.SizeRemaining / 1GB), ($v.Size / 1GB), (1 - $v.SizeRemaining / $v.Size))
)
$opps = $rows | Where-Object { $null -eq $_.SizeGB -or $_.SizeGB -ge 0.05 } | Sort-Object @{ e = { if ($null -eq $_.SizeGB) { -1 } else { $_.SizeGB } } } -Descending

$report = New-Object System.Text.StringBuilder
foreach ($h in $header) { [void]$report.AppendLine($h) }
[void]$report.AppendLine("`n=== Opportunities (largest first; nothing has been deleted) ===")
[void]$report.AppendLine(($opps | Format-Table SizeGB, Area, Item -AutoSize | Out-String -Width 250))
[void]$report.AppendLine("=== How to reclaim each ===")
foreach ($o in $opps) { [void]$report.AppendLine(("[{0,7}] {1} | {2}`n          {3}" -f $(if ($null -eq $o.SizeGB) { '?' } else { "{0:N2}G" -f $o.SizeGB }), $o.Area, $o.Item, $o.Action)) }
if ($games.Count -gt 0) {
    [void]$report.AppendLine("`n=== Installed Steam games (largest first) ===")
    [void]$report.AppendLine(($games | Where-Object Tracked | Sort-Object SizeGB -Descending | Format-Table SizeGB, LastPlayed, Drive, Name -AutoSize | Out-String -Width 250))
}
if ($scan) {
    [void]$report.AppendLine("`n=== Largest folders (>= 0.5 GB) under $sys\, ProgramData, Program Files, and every user profile ===")
    [void]$report.AppendLine('Note: C:\Windows is overstated because WinSxS hard links are counted more than once; trust the ComponentStore (DISM) figure above.')
    [void]$report.AppendLine(($topFolders | Format-Table -AutoSize | Out-String -Width 250))
    [void]$report.AppendLine("=== Largest files (>= $BigFileGB GB) ===")
    [void]$report.AppendLine(($bigFiles | Format-Table -AutoSize | Out-String -Width 250))
}

$text = $report.ToString()
Write-Host ''
Write-Host $text
$outDir = Split-Path $OutFile -Parent
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
Set-Content -LiteralPath $OutFile -Value $text -Encoding UTF8
Write-Host "Report saved to $OutFile" -ForegroundColor Green
