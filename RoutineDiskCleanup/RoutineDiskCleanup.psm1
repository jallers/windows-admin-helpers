<#
.Synopsis
    RoutineDiskCleanup Module
    Collects the easy, low-risk disk space wins on a Windows machine into one audit-and-clean
    workflow that can be run by hand or on a schedule: temp files, crash dumps, package manager
    download caches, shader caches, browser caches, and Windows update leftovers.

    Everything this module touches is regenerable. Nothing here is user data.
#>

# ==========================================
# Private helpers
# ==========================================

function Test-RoutineCleanupIsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RoutineCleanupFiles {
    <#
    .SYNOPSIS
        Enumerates files under a folder without following junctions or symlinks, tolerating
        access-denied subfolders. Returns FileInfo objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [datetime]$OlderThan = [datetime]::MaxValue
    )

    $root = New-Object System.IO.DirectoryInfo($Path)
    if (-not $root.Exists) { return }

    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    $stack.Push($root)

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $files = $null
        $subdirs = $null
        try { $files = $dir.GetFiles() } catch { $files = @() }
        try { $subdirs = $dir.GetDirectories() } catch { $subdirs = @() }

        foreach ($file in $files) {
            if ($file.LastWriteTime -lt $OlderThan) { $file }
        }
        foreach ($sub in $subdirs) {
            # Never descend into reparse points: a junction could point anywhere
            if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                $stack.Push($sub)
            }
        }
    }
}

function Remove-RoutineCleanupFolderContents {
    <#
    .SYNOPSIS
        Deletes files under a folder (never the folder itself), skipping anything locked or
        newer than the cutoff, then prunes directories left empty. Returns freed bytes and counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [datetime]$OlderThan = [datetime]::MaxValue
    )

    $freedBytes = [long]0
    $removed = 0
    $skipped = 0

    foreach ($file in (Get-RoutineCleanupFiles -Path $Path -OlderThan $OlderThan)) {
        try {
            $length = $file.Length
            if ($file.IsReadOnly) { $file.IsReadOnly = $false }
            $file.Delete()
            $freedBytes += $length
            $removed++
        } catch {
            $skipped++
        }
    }

    # Prune empty directories, deepest first. Leave the root alone.
    $dirs = @()
    try {
        $dirs = Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 } |
            Sort-Object { $_.FullName.Length } -Descending
    } catch { }
    foreach ($dir in $dirs) {
        try {
            if (-not (Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction Stop | Select-Object -First 1)) {
                Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction Stop
            }
        } catch { }
    }

    [PSCustomObject]@{
        FreedBytes   = $freedBytes
        RemovedFiles = $removed
        SkippedFiles = $skipped
    }
}

function Get-RoutineCleanupTargets {
    <#
    .SYNOPSIS
        The catalogue of cleanup targets. Path targets are folders whose contents get deleted.
        Command targets run a specific cleanup command instead.
    #>
    $local = $env:LOCALAPPDATA
    $roaming = $env:APPDATA
    $home = $env:USERPROFILE
    $programData = $env:ProgramData
    $windir = $env:SystemRoot

    $targets = @()

    # --- TempFiles: always safe, but skip anything touched in the last day (installers in progress) ---
    $targets += [PSCustomObject]@{ Category='TempFiles'; Method='Path'; Path=(Join-Path $local 'Temp'); MinAgeDays=1; RequiresAdmin=$false; Default=$true
        Description='User temp folder. Files modified in the last 24 hours are left alone.' }
    $targets += [PSCustomObject]@{ Category='TempFiles'; Method='Path'; Path=(Join-Path $windir 'Temp'); MinAgeDays=1; RequiresAdmin=$true; Default=$true
        Description='System temp folder.' }

    # --- CrashReports: dumps and Windows Error Reporting queues ---
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $local 'CrashDumps'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Per-user application crash dumps.' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $local 'Microsoft\Windows\WER\ReportQueue'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Windows Error Reporting reports waiting to be sent (user).' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $local 'Microsoft\Windows\WER\ReportArchive'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Windows Error Reporting archived reports (user).' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $programData 'Microsoft\Windows\WER\ReportQueue'); MinAgeDays=0; RequiresAdmin=$true; Default=$true
        Description='Windows Error Reporting reports waiting to be sent (system).' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $programData 'Microsoft\Windows\WER\ReportArchive'); MinAgeDays=0; RequiresAdmin=$true; Default=$true
        Description='Windows Error Reporting archived reports (system).' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $windir 'Minidump'); MinAgeDays=0; RequiresAdmin=$true; Default=$true
        Description='Kernel minidumps from blue screens.' }
    $targets += [PSCustomObject]@{ Category='CrashReports'; Method='Path'; Path=(Join-Path $windir 'LiveKernelReports'); MinAgeDays=0; RequiresAdmin=$true; Default=$true
        Description='Live kernel reports. Can reach several GB after driver hiccups.' }

    # --- PackageCache: pure download caches. The next install re-fetches what it needs. ---
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'npm-cache\_cacache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='npm download cache.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'pip\cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='pip wheel and HTTP cache.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'uv\cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='uv package cache. Projects hard-link from here, so existing environments keep working.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $home 'scoop\cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Scoop installer download cache.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Command'; Path='scoop cleanup *'; MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Old versions of Scoop apps. Only versions that "current" does not point to are removed. Only runs when Scoop is installed.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $home '.cargo\registry\cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Cargo crate download cache (.crate files).' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'go-build'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Go build cache. Same as "go clean -cache".' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'Yarn\Cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Yarn download cache.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Path'; Path=(Join-Path $local 'NuGet\v3-cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='NuGet HTTP metadata cache.' }
    $targets += [PSCustomObject]@{ Category='PackageCache'; Method='Command'; Path='conda clean --all'; MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Conda tarballs and packages no environment links to. Only runs when conda is installed.' }

    # --- DevDependencyCache (opt-in): larger caches whose loss means a slower next restore/build ---
    $targets += [PSCustomObject]@{ Category='DevDependencyCache'; Method='Path'; Path=(Join-Path $home '.nuget\packages'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='NuGet global packages folder. Next "dotnet restore" re-downloads what each project needs.' }
    $targets += [PSCustomObject]@{ Category='DevDependencyCache'; Method='Path'; Path=(Join-Path $home '.cargo\registry\src'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='Extracted crate sources. Rebuilt from the .crate cache on next build.' }
    $targets += [PSCustomObject]@{ Category='DevDependencyCache'; Method='Path'; Path=(Join-Path $home '.gradle\caches'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='Gradle dependency and build caches.' }

    # --- ShaderCache: GPU drivers rebuild these on the next game launch ---
    $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $local 'NVIDIA\DXCache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='NVIDIA DirectX shader cache.' }
    $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $local 'NVIDIA\GLCache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='NVIDIA OpenGL shader cache.' }
    $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $local 'AMD\DxCache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='AMD DirectX shader cache.' }
    $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $local 'Intel\ShaderCache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Intel shader cache.' }
    $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $local 'D3DSCache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Direct3D shader cache.' }
    $steamRoot = Get-RoutineCleanupSteamRoot
    if ($steamRoot) {
        $targets += [PSCustomObject]@{ Category='ShaderCache'; Method='Path'; Path=(Join-Path $steamRoot 'steamapps\shadercache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
            Description='Steam per-game shader pre-caches. Steam re-downloads or rebuilds them on next launch.' }
    }

    # --- BrowserCache (opt-in): browsers should be closed; locked files are skipped ---
    $browserRoots = @(
        @{ Name='Chrome'; Root=(Join-Path $local 'Google\Chrome\User Data') },
        @{ Name='Edge';   Root=(Join-Path $local 'Microsoft\Edge\User Data') },
        @{ Name='Brave';  Root=(Join-Path $local 'BraveSoftware\Brave-Browser\User Data') }
    )
    foreach ($browser in $browserRoots) {
        if (-not (Test-Path -LiteralPath $browser.Root)) { continue }
        $profiles = Get-ChildItem -LiteralPath $browser.Root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($profile in $profiles) {
            foreach ($sub in 'Cache', 'Code Cache', 'GPUCache') {
                $targets += [PSCustomObject]@{ Category='BrowserCache'; Method='Path'; Path=(Join-Path $profile.FullName $sub); MinAgeDays=0; RequiresAdmin=$false; Default=$false
                    Description="$($browser.Name) $($profile.Name) $sub. Close the browser first." }
            }
        }
    }

    # --- EditorCache (opt-in) ---
    $targets += [PSCustomObject]@{ Category='EditorCache'; Method='Path'; Path=(Join-Path $roaming 'Code\Cache'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='VS Code HTTP cache. Close VS Code first.' }
    $targets += [PSCustomObject]@{ Category='EditorCache'; Method='Path'; Path=(Join-Path $roaming 'Code\CachedData'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='VS Code V8 code cache.' }
    $targets += [PSCustomObject]@{ Category='EditorCache'; Method='Path'; Path=(Join-Path $roaming 'Code\CachedExtensionVSIXs'); MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='Downloaded extension installers VS Code keeps after installing them.' }

    # --- GameLauncher: launcher self-update leftovers, logs, and embedded-browser caches ---
    $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Command'; Path=(Join-Path $programData 'Ubisoft\Ubisoft Game Launcher\patch'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Old Ubisoft Connect self-update builds (~575 MB each, one per launcher update). The build named in patch.txt and the newest build are always kept. Skipped while Ubisoft Connect is running.' }
    $steam = Get-RoutineCleanupSteamRoot
    if ($steam) {
        $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Path'; Path=(Join-Path $steam 'logs'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
            Description='Steam client logs.' }
        $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Path'; Path=(Join-Path $steam 'dumps'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
            Description='Steam client crash dumps.' }
    }
    $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Path'; Path=(Join-Path $local 'Steam\htmlcache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Steam store and overlay browser cache. Close Steam first; locked files are skipped.' }
    $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Path'; Path=(Join-Path $local 'EpicGamesLauncher\Saved\Logs'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Epic Games Launcher logs.' }
    $targets += [PSCustomObject]@{ Category='GameLauncher'; Method='Path'; Path=(Join-Path $local 'EpicGamesLauncher\Saved\webcache'); MinAgeDays=0; RequiresAdmin=$false; Default=$true
        Description='Epic Games Launcher browser cache. Close the launcher first.' }

    # --- WindowsUpdate (admin): leftover downloads and the peer-to-peer cache ---
    $targets += [PSCustomObject]@{ Category='WindowsUpdate'; Method='Command'; Path='Delete-DeliveryOptimizationCache'; MinAgeDays=0; RequiresAdmin=$true; Default=$true
        Description='Delivery Optimization peer cache for Windows and Store updates.' }
    $targets += [PSCustomObject]@{ Category='WindowsUpdate'; Method='Command'; Path=(Join-Path $windir 'SoftwareDistribution\Download'); MinAgeDays=0; RequiresAdmin=$true; Default=$false
        Description='Downloaded update packages. Stops the Windows Update service while clearing, so opt-in only.' }

    # --- ComponentStore (opt-in, admin): WinSxS cleanup via DISM ---
    $targets += [PSCustomObject]@{ Category='ComponentStore'; Method='Command'; Path='DISM /StartComponentCleanup'; MinAgeDays=0; RequiresAdmin=$true; Default=$false
        Description='Removes superseded Windows components from WinSxS (DISM /Online /Cleanup-Image /StartComponentCleanup). Windows runs the same cleanup itself after a 30-day grace; this skips the wait. Slow: several minutes.' }

    # --- RecycleBin (opt-in): technically user data, so never on by default ---
    $targets += [PSCustomObject]@{ Category='RecycleBin'; Method='Command'; Path='Clear-RecycleBin'; MinAgeDays=0; RequiresAdmin=$false; Default=$false
        Description='Empties the Recycle Bin on all drives.' }

    return $targets
}

function ConvertFrom-DismAnalyzeOutput {
    <#
    .SYNOPSIS
        Parses 'DISM /Online /Cleanup-Image /AnalyzeComponentStore' output into the reclaimable size
        and whether DISM itself recommends a cleanup. Labels are the English ones.
    #>
    param([string[]]$Lines)

    $bytes = [long]0
    $recommended = $false
    foreach ($line in $Lines) {
        if ($line -match 'Backups and Disabled Features\s*:\s*([\d.,]+)\s*(KB|MB|GB|TB)') {
            $value = [double]($Matches[1] -replace ',', '')
            $multiplier = switch ($Matches[2]) { 'KB' { 1KB } 'MB' { 1MB } 'GB' { 1GB } 'TB' { 1TB } }
            $bytes = [long]($value * $multiplier)
        } elseif ($line -match 'Component Store Cleanup Recommended\s*:\s*(Yes|No)') {
            $recommended = ($Matches[1] -eq 'Yes')
        }
    }
    [PSCustomObject]@{ Bytes = $bytes; Recommended = $recommended }
}

function Get-RoutineCleanupCommandSize {
    <#
    .SYNOPSIS
        Best-effort size estimate for command-based targets. Returns bytes and file count, or nulls when unknown.
    #>
    param([PSCustomObject]$Target)

    switch -Wildcard ($Target.Path) {
        'scoop cleanup *' {
            $root = Get-RoutineCleanupScoopRoot
            if (-not $root) { return $null }
            $old = @(Get-RoutineCleanupScoopOldVersions -ScoopRoot $root)
            if ($old.Count -eq 0) { return $null }
            $apps = @($old | Select-Object -ExpandProperty App -Unique).Count
            return [PSCustomObject]@{ Bytes = ($old | Measure-Object -Property Bytes -Sum).Sum; Files = ($old | Measure-Object -Property Files -Sum).Sum; Note = "$($old.Count) old versions across $apps apps" }
        }
        'DISM /StartComponentCleanup' {
            if (-not (Test-RoutineCleanupIsElevated)) { return $null }
            $output = & "$env:SystemRoot\System32\Dism.exe" /Online /Cleanup-Image /AnalyzeComponentStore 2>&1
            if ($LASTEXITCODE -ne 0) { return $null }
            $analysis = ConvertFrom-DismAnalyzeOutput -Lines ([string[]]$output)
            $note = ''
            if (-not $analysis.Recommended) { $note = 'size is an estimate; DISM does not currently recommend a cleanup' }
            return [PSCustomObject]@{ Bytes = $analysis.Bytes; Files = 1; Note = $note }
        }
        'conda clean*' {
            $conda = Get-RoutineCleanupCondaExe
            if (-not $conda) { return $null }
            $pkgs = Join-Path (Split-Path (Split-Path $conda -Parent) -Parent) 'pkgs'
            if (-not (Test-Path -LiteralPath $pkgs)) { return $null }
            $files = @(Get-RoutineCleanupFiles -Path $pkgs)
            $bytes = ($files | Measure-Object -Property Length -Sum).Sum
            # conda keeps packages that environments link to, so this is an upper bound
            return [PSCustomObject]@{ Bytes = $bytes; Files = $files.Count; Note = 'size is an upper bound; conda keeps packages that environments still link to' }
        }
        'Delete-DeliveryOptimizationCache' {
            $cache = Join-Path $env:ProgramData 'Microsoft\Windows\DeliveryOptimization\Cache'
            $files = @(Get-RoutineCleanupFiles -Path $cache)
            if ($files.Count -eq 0) { return $null }
            return [PSCustomObject]@{ Bytes = ($files | Measure-Object -Property Length -Sum).Sum; Files = $files.Count; Note = '' }
        }
        '*Ubisoft Game Launcher\patch' {
            $old = Get-RoutineCleanupUbisoftOldPatches -PatchRoot $Target.Path
            if ($null -eq $old) { return $null }
            $old = @($old)
            $note = ''
            if ($old.Count -gt 0) { $note = "$($old.Count) old builds: $(($old | Select-Object -ExpandProperty Build) -join ', ')" }
            return [PSCustomObject]@{ Bytes = [long]($old | Measure-Object -Property Bytes -Sum).Sum; Files = [int]($old | Measure-Object -Property Files -Sum).Sum; Note = $note }
        }
        '*SoftwareDistribution\Download' {
            $files = @(Get-RoutineCleanupFiles -Path $Target.Path)
            if ($files.Count -eq 0) { return $null }
            return [PSCustomObject]@{ Bytes = ($files | Measure-Object -Property Length -Sum).Sum; Files = $files.Count; Note = '' }
        }
        'Clear-RecycleBin' {
            try {
                $shell = New-Object -ComObject Shell.Application
                $bin = $shell.Namespace(0xA)
                $bytes = [long]0
                $count = 0
                foreach ($item in $bin.Items()) {
                    $count++
                    if ($item.IsFolder) {
                        $bytes += (Get-RoutineCleanupFiles -Path $item.Path | Measure-Object -Property Length -Sum).Sum
                    } else {
                        $bytes += $item.Size
                    }
                }
                if ($count -eq 0) { return $null }
                return [PSCustomObject]@{ Bytes = $bytes; Files = $count; Note = '' }
            } catch { return $null }
        }
    }
    return $null
}

function Get-RoutineCleanupScoopRoot {
    if ($env:SCOOP -and (Test-Path -LiteralPath $env:SCOOP)) { return $env:SCOOP }
    $default = Join-Path $env:USERPROFILE 'scoop'
    if (Test-Path -LiteralPath (Join-Path $default 'apps')) { return $default }
    return $null
}

function Get-RoutineCleanupScoopOldVersions {
    <#
    .SYNOPSIS
        Lists the non-current version folders of every Scoop app, with sizes. Mirrors what
        'scoop cleanup *' would remove without invoking Scoop.
    #>
    param([string]$ScoopRoot)

    $appsRoot = Join-Path $ScoopRoot 'apps'
    if (-not (Test-Path -LiteralPath $appsRoot)) { return @() }

    $old = @()
    foreach ($app in (Get-ChildItem -LiteralPath $appsRoot -Directory -ErrorAction SilentlyContinue)) {
        if ($app.Name -eq 'scoop') { continue }
        $currentLink = Join-Path $app.FullName 'current'
        $currentName = $null
        if (Test-Path -LiteralPath $currentLink) {
            try {
                $target = (Get-Item -LiteralPath $currentLink -Force).Target
                if ($target -is [array]) { $target = $target[0] }
                if ($target) { $currentName = Split-Path $target -Leaf }
            } catch { }
        }
        # Without a resolvable "current" we can't tell which version is live, so skip the app
        if (-not $currentName) { continue }

        $versions = Get-ChildItem -LiteralPath $app.FullName -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne 'current' -and $_.Name -ne $currentName -and (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) }
        foreach ($v in $versions) {
            $files = @(Get-RoutineCleanupFiles -Path $v.FullName)
            $bytes = [long]0
            if ($files.Count -gt 0) { $bytes = ($files | Measure-Object -Property Length -Sum).Sum }
            $old += [PSCustomObject]@{ App = $app.Name; Version = $v.Name; Path = $v.FullName; Bytes = $bytes; Files = $files.Count }
        }
    }
    return $old
}

function Get-RoutineCleanupSteamRoot {
    try {
        $path = (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -Name SteamPath -ErrorAction Stop).SteamPath
        if ($path) {
            $path = $path -replace '/', '\'
            if (Test-Path -LiteralPath $path) { return $path }
        }
    } catch { }
    $default = Join-Path ${env:ProgramFiles(x86)} 'Steam'
    if (Test-Path -LiteralPath (Join-Path $default 'steam.exe')) { return $default }
    return $null
}

function Test-RoutineCleanupUbisoftRunning {
    return [bool](Get-Process -Name 'upc', 'UbisoftConnect', 'UplayWebCore', 'UplayService' -ErrorAction SilentlyContinue)
}

function Get-RoutineCleanupUbisoftOldPatches {
    <#
    .SYNOPSIS
        Lists Ubisoft Connect self-update build folders that are neither the build patch.txt names
        nor the newest build. Returns $null when the current build can't be determined, so nothing
        is ever removed on a guess.
    #>
    param([string]$PatchRoot)

    if (-not (Test-Path -LiteralPath $PatchRoot)) { return $null }

    # patch.txt starts with the current build number, followed by that build's file list
    $current = $null
    try { $current = (Get-Content -LiteralPath (Join-Path $PatchRoot 'patch.txt') -TotalCount 1 -ErrorAction Stop).Trim() } catch { }
    if (-not ($current -match '^\d+$')) { return $null }

    $builds = @(Get-ChildItem -LiteralPath $PatchRoot -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+$' -and (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) })
    if ($builds.Count -eq 0) { return @() }

    # Also keep the newest build, in case a download is newer than what patch.txt records
    $newest = ($builds | Sort-Object { [long]$_.Name } -Descending | Select-Object -First 1).Name

    $old = @()
    foreach ($b in ($builds | Where-Object { $_.Name -ne $current -and $_.Name -ne $newest })) {
        $files = @(Get-RoutineCleanupFiles -Path $b.FullName)
        $bytes = [long]0
        if ($files.Count -gt 0) { $bytes = ($files | Measure-Object -Property Length -Sum).Sum }
        $old += [PSCustomObject]@{ Build = $b.Name; Path = $b.FullName; Bytes = $bytes; Files = $files.Count }
    }
    return $old
}

function Get-RoutineCleanupCondaExe {
    foreach ($candidate in @(
        (Join-Path $env:USERPROFILE 'miniconda3\Scripts\conda.exe'),
        (Join-Path $env:USERPROFILE 'anaconda3\Scripts\conda.exe'),
        (Join-Path $env:LOCALAPPDATA 'miniconda3\Scripts\conda.exe'),
        'C:\ProgramData\miniconda3\Scripts\conda.exe',
        'C:\ProgramData\anaconda3\Scripts\conda.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $cmd = Get-Command conda.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-RoutineCleanupCommand {
    <#
    .SYNOPSIS
        Runs a command-based target. Returns freed bytes (best effort) and a message.
    #>
    param(
        [PSCustomObject]$Item,
        [switch]$ResetBase
    )

    $before = Get-RoutineCleanupCommandSize -Target $Item
    $beforeBytes = 0
    if ($before) { $beforeBytes = $before.Bytes }

    switch -Wildcard ($Item.Path) {
        'scoop cleanup *' {
            $root = Get-RoutineCleanupScoopRoot
            if (-not $root) { return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'Scoop not found.' } }
            $scoopScript = Join-Path $root 'apps\scoop\current\bin\scoop.ps1'
            if (-not (Test-Path -LiteralPath $scoopScript)) {
                $cmd = Get-Command scoop -ErrorAction SilentlyContinue
                if ($cmd) { $scoopScript = $cmd.Source } else { return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'scoop command not found.' } }
            }
            $output = & $scoopScript cleanup * 2>&1
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Failed'; Message = (($output | Select-Object -Last 3) -join ' ') -replace '\s+', ' ' }
            }
        }
        'DISM /StartComponentCleanup' {
            $dismArgs = @('/Online', '/Cleanup-Image', '/StartComponentCleanup', '/NoRestart')
            if ($ResetBase) { $dismArgs += '/ResetBase' }
            $output = & "$env:SystemRoot\System32\Dism.exe" @dismArgs 2>&1
            $code = $LASTEXITCODE
            if ($code -eq 3010) {
                # Success, restart required to finish
                $after = Get-RoutineCleanupCommandSize -Target $Item
                $afterBytes = 0
                if ($after) { $afterBytes = $after.Bytes }
                return [PSCustomObject]@{ FreedBytes = [math]::Max(0, $beforeBytes - $afterBytes); Status = 'Removed'; Message = 'Completed. A restart is required to finish the cleanup.' }
            }
            if ($code -ne 0) {
                $tail = (($output | Select-Object -Last 3) -join ' ') -replace '\s+', ' '
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Failed'; Message = "DISM exited with $code. $tail" }
            }
        }
        'conda clean*' {
            $conda = Get-RoutineCleanupCondaExe
            if (-not $conda) { return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'conda not found.' } }
            $output = & $conda clean --all --yes 2>&1
            if ($LASTEXITCODE -ne 0) {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Failed'; Message = (($output | Out-String).Trim() -replace '\s+', ' ') }
            }
        }
        'Delete-DeliveryOptimizationCache' {
            if (-not (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue)) {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'Delete-DeliveryOptimizationCache cmdlet not available on this Windows build.' }
            }
            try { Delete-DeliveryOptimizationCache -Force -ErrorAction Stop } catch {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Failed'; Message = $_.Exception.Message }
            }
        }
        '*Ubisoft Game Launcher\patch' {
            if (Test-RoutineCleanupUbisoftRunning) {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'Ubisoft Connect is running; close it and run again.' }
            }
            $old = Get-RoutineCleanupUbisoftOldPatches -PatchRoot $Item.Path
            if ($null -eq $old) {
                return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = 'Could not read the current build from patch.txt; nothing removed.' }
            }
            $freed = [long]0
            $removedBuilds = 0
            $skipped = 0
            foreach ($build in @($old)) {
                # Clear contents without following reparse points, then drop the emptied build folder
                $r = Remove-RoutineCleanupFolderContents -Path $build.Path
                $freed += $r.FreedBytes
                $skipped += $r.SkippedFiles
                # Non-recursive delete: only succeeds if pruning left the folder truly empty
                try { [System.IO.Directory]::Delete($build.Path, $false); $removedBuilds++ } catch { }
            }
            $status = 'Removed'
            if ($skipped -gt 0) { $status = 'PartiallyRemoved' }
            return [PSCustomObject]@{ FreedBytes = $freed; Status = $status; Message = "Removed $removedBuilds old builds, skipped $skipped locked files." }
        }
        '*SoftwareDistribution\Download' {
            $services = @('wuauserv', 'bits')
            $wasRunning = @()
            foreach ($svc in $services) {
                $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($s -and $s.Status -eq 'Running') { $wasRunning += $svc; Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
            }
            try {
                $result = Remove-RoutineCleanupFolderContents -Path $Item.Path
            } finally {
                foreach ($svc in $wasRunning) { Start-Service -Name $svc -ErrorAction SilentlyContinue }
            }
            return [PSCustomObject]@{ FreedBytes = $result.FreedBytes; Status = 'Removed'; Message = "Removed $($result.RemovedFiles) files, skipped $($result.SkippedFiles)." }
        }
        'Clear-RecycleBin' {
            try { Clear-RecycleBin -Force -ErrorAction Stop } catch {
                # Clear-RecycleBin throws when the bin is already empty on some builds
                if ($_.Exception.Message -notmatch 'empty') {
                    return [PSCustomObject]@{ FreedBytes = 0; Status = 'Failed'; Message = $_.Exception.Message }
                }
            }
        }
        default {
            return [PSCustomObject]@{ FreedBytes = 0; Status = 'Skipped'; Message = "Unknown command target '$($Item.Path)'." }
        }
    }

    $after = Get-RoutineCleanupCommandSize -Target $Item
    $afterBytes = 0
    if ($after) { $afterBytes = $after.Bytes }
    $freed = [math]::Max(0, $beforeBytes - $afterBytes)
    return [PSCustomObject]@{ FreedBytes = $freed; Status = 'Removed'; Message = 'Completed.' }
}

# ==========================================
# Public cmdlets
# ==========================================

function Get-RoutineDiskCleanupInfo {
    <#
    .SYNOPSIS
        Audits the easy disk space wins on this machine and reports what each would free.
    .DESCRIPTION
        Walks a catalogue of regenerable caches and leftovers: temp files, crash reports, package manager
        download caches, GPU shader caches, browser and editor caches, Windows Update leftovers, and the
        Recycle Bin. Reports size and file count per location without deleting anything.

        By default only the categories that are safe to clear at any time are included. Opt-in categories
        (DevDependencyCache, BrowserCache, EditorCache, RecycleBin, and the SoftwareDistribution part of
        WindowsUpdate) must be requested with -Category or -IncludeAll.
    .PARAMETER Category
        Restrict the audit to these categories. Naming a category includes it even if it is opt-in.
    .PARAMETER IncludeAll
        Include every category, opt-in ones too.
    .PARAMETER MinimumAgeDays
        Only count files last modified at least this many days ago. Temp folders always use at least 1 day.
    .PARAMETER IncludeEmpty
        Also list locations that exist but currently hold nothing to clean.
    .EXAMPLE
        Get-RoutineDiskCleanupInfo
    .EXAMPLE
        Get-RoutineDiskCleanupInfo -IncludeAll | Sort-Object SizeMB -Descending | Format-Table
    .EXAMPLE
        Get-RoutineDiskCleanupInfo -Category PackageCache, ShaderCache -MinimumAgeDays 7
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('TempFiles', 'CrashReports', 'PackageCache', 'DevDependencyCache', 'ShaderCache', 'BrowserCache', 'EditorCache', 'GameLauncher', 'WindowsUpdate', 'ComponentStore', 'RecycleBin')]
        [string[]]$Category,

        [Parameter()]
        [switch]$IncludeAll,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$MinimumAgeDays = 0,

        [Parameter()]
        [switch]$IncludeEmpty
    )

    process {
        $targets = Get-RoutineCleanupTargets
        if ($Category) {
            $targets = $targets | Where-Object { $_.Category -in $Category }
        } elseif (-not $IncludeAll) {
            $targets = $targets | Where-Object { $_.Default }
        }

        $elevated = Test-RoutineCleanupIsElevated
        $now = Get-Date

        foreach ($target in $targets) {
            $ageDays = [math]::Max($MinimumAgeDays, $target.MinAgeDays)
            $cutoff = $now.AddDays(-$ageDays)
            $bytes = [long]0
            $count = 0
            $note = ''

            if ($target.Method -eq 'Path') {
                if (-not (Test-Path -LiteralPath $target.Path)) { continue }
                $files = @(Get-RoutineCleanupFiles -Path $target.Path -OlderThan $cutoff)
                $count = $files.Count
                if ($count -gt 0) { $bytes = ($files | Measure-Object -Property Length -Sum).Sum }
            } else {
                $sizeUnknown = $false
                $estimate = Get-RoutineCleanupCommandSize -Target $target
                if ($estimate) {
                    $bytes = $estimate.Bytes
                    $count = $estimate.Files
                    $note = $estimate.Note
                } elseif ($target.Path -like 'conda clean*' -and -not (Get-RoutineCleanupCondaExe)) {
                    continue
                } elseif ($target.Path -like 'scoop cleanup*' -and -not (Get-RoutineCleanupScoopRoot)) {
                    continue
                } elseif ($target.Path -like '*Ubisoft Game Launcher\patch' -and -not (Test-Path -LiteralPath $target.Path)) {
                    continue
                } elseif ($target.RequiresAdmin -and -not $elevated) {
                    # Can't measure without elevation; still list it so the user knows it exists
                    $sizeUnknown = $true
                }
            }

            if ($count -eq 0 -and -not $IncludeEmpty -and -not $sizeUnknown) { continue }

            $description = $target.Description
            if ($note) { $description += " ($note)" }
            if ($sizeUnknown) { $description += ' Size unknown until run elevated.' }
            elseif ($target.RequiresAdmin -and -not $elevated) { $description += ' Requires an elevated session.' }

            [PSCustomObject]@{
                Category      = $target.Category
                Path          = $target.Path
                Method        = $target.Method
                FileCount     = $count
                SizeMB        = [math]::Round($bytes / 1MB, 2)
                MinAgeDays    = $ageDays
                RequiresAdmin = $target.RequiresAdmin
                Description   = $description
            }
        }
    }
}

function Invoke-RoutineDiskCleanup {
    <#
    .SYNOPSIS
        Clears the easy disk space wins found by Get-RoutineDiskCleanupInfo.
    .DESCRIPTION
        Deletes the contents of each audited location (never the folder itself), skipping files that are
        locked or newer than the age cutoff, then prunes empty subfolders. Command-based targets run their
        native cleanup instead. Locations that need elevation are skipped with a warning when the session
        is not elevated, so an unelevated run still does everything it can.

        Supports -WhatIf and -Confirm. Because ConfirmImpact is High, an interactive run prompts per
        location unless -Confirm:$false is passed, which is what a scheduled run should do.
    .PARAMETER CleanupItem
        Items from Get-RoutineDiskCleanupInfo. When omitted, the audit runs with the same parameters.
    .PARAMETER Category
        Categories to clean when not piping input.
    .PARAMETER IncludeAll
        Clean every category, opt-in ones too, when not piping input.
    .PARAMETER MinimumAgeDays
        Only delete files last modified at least this many days ago. Temp folders always use at least 1 day.
    .PARAMETER PassThru
        Emit one result object per location instead of just the summary line.
    .PARAMETER ResetBase
        For the ComponentStore category only: add /ResetBase to the DISM cleanup. This permanently
        removes every superseded component, which frees the most space but means installed updates
        can no longer be uninstalled. Not for scheduled runs; the scheduler never sets it.
    .EXAMPLE
        Get-RoutineDiskCleanupInfo | Invoke-RoutineDiskCleanup -WhatIf
    .EXAMPLE
        Invoke-RoutineDiskCleanup -Confirm:$false
    .EXAMPLE
        Invoke-RoutineDiskCleanup -Category BrowserCache, EditorCache -PassThru
    .EXAMPLE
        Invoke-RoutineDiskCleanup -Category ComponentStore -ResetBase
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [PSCustomObject]$CleanupItem,

        [Parameter()]
        [ValidateSet('TempFiles', 'CrashReports', 'PackageCache', 'DevDependencyCache', 'ShaderCache', 'BrowserCache', 'EditorCache', 'GameLauncher', 'WindowsUpdate', 'ComponentStore', 'RecycleBin')]
        [string[]]$Category,

        [Parameter()]
        [switch]$IncludeAll,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$MinimumAgeDays = 0,

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$ResetBase
    )

    begin {
        $items = @()
    }

    process {
        if ($CleanupItem) { $items += $CleanupItem }
    }

    end {
        # Only audit ourselves when nothing was piped in. An upstream audit that found nothing
        # must not turn into a full default cleanup.
        if ($items.Count -eq 0 -and -not $MyInvocation.ExpectingInput) {
            $auditParams = @{ MinimumAgeDays = $MinimumAgeDays }
            if ($Category) { $auditParams['Category'] = $Category }
            if ($IncludeAll) { $auditParams['IncludeAll'] = $true }
            $items = @(Get-RoutineDiskCleanupInfo @auditParams)
        }

        if ($items.Count -eq 0) {
            Write-Host "Nothing to clean." -ForegroundColor Green
            return
        }

        $elevated = Test-RoutineCleanupIsElevated
        $totalFreed = [long]0
        $results = @()

        foreach ($item in $items) {
            # In a dry run, show elevated-only work too; only a real run has to skip it
            if ($item.RequiresAdmin -and -not $elevated -and -not $WhatIfPreference) {
                Write-Warning "Skipping $($item.Category) '$($item.Path)': requires an elevated session."
                $results += [PSCustomObject]@{ Category=$item.Category; Path=$item.Path; FreedMB=0; RemovedFiles=0; SkippedFiles=0; Status='SkippedNeedsAdmin'; Message='Not elevated.' }
                continue
            }

            $label = "$($item.Category) at '$($item.Path)' ($($item.FileCount) files, $($item.SizeMB) MB)"
            if ($ResetBase -and $item.Path -eq 'DISM /StartComponentCleanup') { $label += ' with /ResetBase (updates become un-uninstallable)' }
            if (-not $PSCmdlet.ShouldProcess($item.Path, "Clean $label")) { continue }

            Write-Host "Cleaning $label..." -ForegroundColor Cyan

            if ($item.Method -eq 'Command') {
                $outcome = Invoke-RoutineCleanupCommand -Item $item -ResetBase:$ResetBase
                $freedMB = [math]::Round($outcome.FreedBytes / 1MB, 2)
                $totalFreed += $outcome.FreedBytes
                $results += [PSCustomObject]@{ Category=$item.Category; Path=$item.Path; FreedMB=$freedMB; RemovedFiles=$null; SkippedFiles=$null; Status=$outcome.Status; Message=$outcome.Message }
                continue
            }

            $ageDays = 0
            if ($item.PSObject.Properties['MinAgeDays']) { $ageDays = [int]$item.MinAgeDays }
            $ageDays = [math]::Max($ageDays, $MinimumAgeDays)
            $cutoff = (Get-Date).AddDays(-$ageDays)

            $outcome = Remove-RoutineCleanupFolderContents -Path $item.Path -OlderThan $cutoff
            $totalFreed += $outcome.FreedBytes
            $status = 'Removed'
            if ($outcome.SkippedFiles -gt 0 -and $outcome.RemovedFiles -eq 0) { $status = 'Locked' }
            elseif ($outcome.SkippedFiles -gt 0) { $status = 'PartiallyRemoved' }

            $results += [PSCustomObject]@{
                Category     = $item.Category
                Path         = $item.Path
                FreedMB      = [math]::Round($outcome.FreedBytes / 1MB, 2)
                RemovedFiles = $outcome.RemovedFiles
                SkippedFiles = $outcome.SkippedFiles
                Status       = $status
                Message      = "Removed $($outcome.RemovedFiles) files, skipped $($outcome.SkippedFiles) (locked or in use)."
            }
        }

        if ($results.Count -gt 0 -and -not $WhatIfPreference) {
            Write-Host ("Freed {0:N0} MB across {1} locations." -f ($totalFreed / 1MB), @($results | Where-Object { $_.Status -ne 'SkippedNeedsAdmin' }).Count) -ForegroundColor Green
        }
        if ($PassThru) { $results }
    }
}

function Register-RoutineDiskCleanupTask {
    <#
    .SYNOPSIS
        Creates a scheduled task that runs Invoke-RoutineDiskCleanup on a schedule.
    .DESCRIPTION
        Registers a task under the current user that imports this module and runs the cleanup
        non-interactively, appending a log line per run. Register from an elevated session with
        -RunElevated to let the task clean system locations too.
    .PARAMETER Category
        Categories to clean. Defaults to the module's default set.
    .PARAMETER IncludeAll
        Clean every category, opt-in ones too. Think twice before scheduling BrowserCache or RecycleBin.
    .PARAMETER MinimumAgeDays
        Age cutoff passed to the cleanup. Defaults to 7 for scheduled runs, which keeps recent caches warm.
    .PARAMETER DayOfWeek
        Day to run. Defaults to Sunday.
    .PARAMETER At
        Time of day to run. Defaults to 03:00.
    .PARAMETER LogPath
        Log file to append to. Defaults to %LOCALAPPDATA%\RoutineDiskCleanup\cleanup.log.
    .PARAMETER RunElevated
        Register the task to run with highest privileges. Requires an elevated session to register.
    .PARAMETER TaskName
        Name of the scheduled task. Defaults to 'RoutineDiskCleanup'.
    .EXAMPLE
        Register-RoutineDiskCleanupTask
    .EXAMPLE
        Register-RoutineDiskCleanupTask -Category TempFiles, PackageCache, ShaderCache -DayOfWeek Saturday -At '04:30' -RunElevated
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [ValidateSet('TempFiles', 'CrashReports', 'PackageCache', 'DevDependencyCache', 'ShaderCache', 'BrowserCache', 'EditorCache', 'GameLauncher', 'WindowsUpdate', 'ComponentStore', 'RecycleBin')]
        [string[]]$Category,

        [Parameter()]
        [switch]$IncludeAll,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$MinimumAgeDays = 7,

        [Parameter()]
        [System.DayOfWeek]$DayOfWeek = [System.DayOfWeek]::Sunday,

        [Parameter()]
        [string]$At = '03:00',

        [Parameter()]
        [string]$LogPath = (Join-Path $env:LOCALAPPDATA 'RoutineDiskCleanup\cleanup.log'),

        [Parameter()]
        [switch]$RunElevated,

        [Parameter()]
        [string]$TaskName = 'RoutineDiskCleanup'
    )

    $manifest = Join-Path $PSScriptRoot 'RoutineDiskCleanup.psd1'
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $cleanupArgs = "-MinimumAgeDays $MinimumAgeDays -Confirm:`$false -PassThru"
    if ($IncludeAll) { $cleanupArgs += ' -IncludeAll' }
    elseif ($Category) { $cleanupArgs += " -Category $($Category -join ',')" }

    # The task runs a one-line script: import, clean, append a summary to the log
    $script = "Import-Module '$manifest' -Force; " +
              "`$r = Invoke-RoutineDiskCleanup $cleanupArgs; " +
              "`$freed = (`$r | Measure-Object FreedMB -Sum).Sum; " +
              "Add-Content -LiteralPath '$LogPath' -Value ((Get-Date -Format s) + ' freed ' + [math]::Round(`$freed) + ' MB across ' + @(`$r).Count + ' locations')"

    $shell = 'powershell.exe'
    if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { $shell = (Get-Command pwsh.exe).Source }

    $action = New-ScheduledTaskAction -Execute $shell -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$script`""
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $At
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfIdle:$false -WakeToRun:$false -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
    $runLevel = 'Limited'
    if ($RunElevated) { $runLevel = 'Highest' }
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel $runLevel

    if ($PSCmdlet.ShouldProcess($TaskName, "Register weekly cleanup task ($DayOfWeek at $At, log: $LogPath)")) {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
        Write-Host "Registered task '$TaskName': every $DayOfWeek at $At. Log: $LogPath" -ForegroundColor Green
    }
}

function Unregister-RoutineDiskCleanupTask {
    <#
    .SYNOPSIS
        Removes the scheduled task created by Register-RoutineDiskCleanupTask.
    .PARAMETER TaskName
        Name of the scheduled task. Defaults to 'RoutineDiskCleanup'.
    .EXAMPLE
        Unregister-RoutineDiskCleanupTask
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [string]$TaskName = 'RoutineDiskCleanup'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Warning "No scheduled task named '$TaskName' found."
        return
    }
    if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed task '$TaskName'." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-RoutineDiskCleanupInfo, Invoke-RoutineDiskCleanup, Register-RoutineDiskCleanupTask, Unregister-RoutineDiskCleanupTask
