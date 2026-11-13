<#
.Synopsis
    NvidiaUpdateCleaner Module
    Audits and cleans up residual setup files, installer package caches, download leftovers,
    log files, shader caches, and superseded driver-store packages created by NVIDIA driver
    updates and software installations.
#>

# Export Aliases
Set-Alias -Name Get-NvidiaCleanupInfo -Value Get-NvidiaUpdateCleanupInfo -Scope Global
Set-Alias -Name Remove-NvidiaCleanupItem -Value Remove-NvidiaUpdateCleanupItem -Scope Global

# ==========================================
# Private helpers
# ==========================================

function Test-NvidiaCleanerIsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertFrom-PnpUtilDriverList {
    <#
    .SYNOPSIS
        Parses the text output of 'pnputil /enum-drivers' into objects.
    .NOTES
        pnputil prints one block per package separated by blank lines, with "Label: value" rows.
        Labels are matched on the English names; localized Windows builds may need adjusting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [string[]]$Lines
    )

    $packages = @()
    $current = $null

    foreach ($line in $Lines) {
        if ($line -match '^\s*Published Name:\s*(.+?)\s*$') {
            if ($current) { $packages += $current }
            $current = [PSCustomObject]@{
                PublishedName = $Matches[1]
                OriginalName  = $null
                ProviderName  = $null
                ClassName     = $null
                DriverDate    = $null
                DriverVersion = $null
            }
            continue
        }
        if (-not $current) { continue }

        if ($line -match '^\s*Original Name:\s*(.+?)\s*$') {
            $current.OriginalName = $Matches[1]
        } elseif ($line -match '^\s*Provider Name:\s*(.+?)\s*$') {
            $current.ProviderName = $Matches[1]
        } elseif ($line -match '^\s*Class Name:\s*(.+?)\s*$') {
            $current.ClassName = $Matches[1]
        } elseif ($line -match '^\s*Driver Version:\s*(\S+)\s+(\S+)\s*$') {
            # pnputil prints the date in the current culture's short format
            try { $current.DriverDate = [datetime]::Parse($Matches[1]) } catch { $current.DriverDate = $null }
            $current.DriverVersion = $Matches[2]
        }
    }
    if ($current) { $packages += $current }

    return $packages
}

function Get-NvidiaDriverStorePackage {
    <#
    .SYNOPSIS
        Lists NVIDIA driver packages in the Windows driver store and reports which ones are in use,
        which are superseded by a newer package of the same family, and how much space each takes.
    .DESCRIPTION
        Every NVIDIA driver update leaves the previous package in C:\Windows\System32\DriverStore.
        Display driver packages are 2 to 3 GB each, so two or three leftovers can outweigh every other
        NVIDIA cache combined. Windows never removes them on its own.

        Each package is classified as:
          InUse       - a present device is currently bound to this package. Never removed.
          Superseded  - an older package of a family that also has a newer package. Safe to remove.
          Unused      - the newest package of its family, but no present device is bound to it.
                        Usually an older driver generation (for example nv_dispi.inf after the GPU moved
                        to nvmdi.inf) or hardware that is no longer connected. Removed only on request.

        Reading the driver store and the in-use mapping does not require elevation.
    .PARAMETER Provider
        Wildcard matched against the package's Provider Name. Defaults to 'NVIDIA*'.
    .PARAMETER Status
        Return only packages with the given status values.
    .EXAMPLE
        Get-NvidiaDriverStorePackage
    .EXAMPLE
        Get-NvidiaDriverStorePackage -Status Superseded, Unused | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Provider = 'NVIDIA*',

        [Parameter()]
        [ValidateSet('InUse', 'Superseded', 'Unused')]
        [string[]]$Status
    )

    process {
        $pnputilOutput = & "$env:SystemRoot\System32\pnputil.exe" /enum-drivers 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "pnputil /enum-drivers failed with exit code $LASTEXITCODE."
            return
        }

        $packages = ConvertFrom-PnpUtilDriverList -Lines ([string[]]$pnputilOutput) |
            Where-Object { $_.ProviderName -like $Provider }

        if (-not $packages) {
            Write-Verbose "No driver-store packages found for provider '$Provider'."
            return
        }

        # Which published infs are bound to a present device right now
        $inUseInfs = @{}
        Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.InfName } |
            ForEach-Object { $inUseInfs[$_.InfName.ToLowerInvariant()] = $true }

        # Map each package to its FileRepository folder by hashing the published inf against the
        # inf inside each candidate folder. Folder names are <originalname>_<arch>_<hash>.
        $repositoryRoot = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
        $infRoot = Join-Path $env:SystemRoot 'INF'
        $folderHashCache = @{}

        $results = foreach ($pkg in $packages) {
            $folder = $null
            $sizeBytes = 0
            $fileCount = 0

            $publishedInfPath = Join-Path $infRoot $pkg.PublishedName
            $publishedHash = $null
            if ($pkg.OriginalName -and (Test-Path -LiteralPath $publishedInfPath)) {
                try { $publishedHash = (Get-FileHash -LiteralPath $publishedInfPath -Algorithm SHA256).Hash } catch { }
            }

            if ($publishedHash) {
                $family = [System.IO.Path]::GetFileNameWithoutExtension($pkg.OriginalName)
                $candidates = Get-ChildItem -LiteralPath $repositoryRoot -Directory -Filter "$family.inf_*" -ErrorAction SilentlyContinue
                foreach ($candidate in $candidates) {
                    $candidateInf = Join-Path $candidate.FullName $pkg.OriginalName
                    if (-not (Test-Path -LiteralPath $candidateInf)) { continue }
                    if (-not $folderHashCache.ContainsKey($candidateInf)) {
                        try {
                            $folderHashCache[$candidateInf] = (Get-FileHash -LiteralPath $candidateInf -Algorithm SHA256).Hash
                        } catch {
                            $folderHashCache[$candidateInf] = $null
                        }
                    }
                    if ($folderHashCache[$candidateInf] -eq $publishedHash) {
                        $folder = $candidate.FullName
                        break
                    }
                }
            }

            if ($folder) {
                $files = Get-ChildItem -LiteralPath $folder -Recurse -Force -File -ErrorAction SilentlyContinue
                if ($files) {
                    $fileCount = @($files).Count
                    $sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
                }
            }

            [PSCustomObject]@{
                PublishedName = $pkg.PublishedName
                OriginalName  = $pkg.OriginalName
                ProviderName  = $pkg.ProviderName
                ClassName     = $pkg.ClassName
                DriverDate    = $pkg.DriverDate
                DriverVersion = $pkg.DriverVersion
                InUse         = $inUseInfs.ContainsKey($pkg.PublishedName.ToLowerInvariant())
                Status        = $null
                Path          = $folder
                FileCount     = $fileCount
                SizeMB        = [math]::Round($sizeBytes / 1MB, 2)
            }
        }

        # Classify within each family (same OriginalName): newest by date, then version
        $results | Group-Object OriginalName | ForEach-Object {
            $sorted = $_.Group | Sort-Object -Property @{ Expression = 'DriverDate'; Descending = $true },
                                                      @{ Expression = { try { [version]$_.DriverVersion } catch { [version]'0.0' } }; Descending = $true }
            $newest = $sorted | Select-Object -First 1
            foreach ($item in $_.Group) {
                if ($item.InUse) {
                    $item.Status = 'InUse'
                } elseif ($item.PublishedName -eq $newest.PublishedName) {
                    $item.Status = 'Unused'
                } else {
                    $item.Status = 'Superseded'
                }
            }
        }

        if ($Status) {
            $results = $results | Where-Object { $_.Status -in $Status }
        }

        $results | Sort-Object OriginalName, @{ Expression = 'DriverDate'; Descending = $true }
    }
}

function Remove-NvidiaDriverStorePackage {
    <#
    .SYNOPSIS
        Removes superseded NVIDIA packages from the Windows driver store using pnputil.
    .DESCRIPTION
        Deletes driver-store packages that no present device is bound to. In-use packages are always
        skipped. By default only Superseded packages are removed; pass -IncludeUnused to also remove
        packages that are the newest of their family but have no device bound to them.

        pnputil is called without /force, so Windows itself refuses to delete anything still in use.
        Requires an elevated PowerShell session unless -WhatIf is used.
    .PARAMETER Package
        Package objects from Get-NvidiaDriverStorePackage. When omitted, the driver store is queried.
    .PARAMETER IncludeUnused
        Also remove packages classified as Unused.
    .EXAMPLE
        Get-NvidiaDriverStorePackage | Remove-NvidiaDriverStorePackage -WhatIf
    .EXAMPLE
        Remove-NvidiaDriverStorePackage -IncludeUnused
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [PSCustomObject]$Package,

        [Parameter()]
        [switch]$IncludeUnused
    )

    begin {
        $packages = @()
    }

    process {
        if ($Package) { $packages += $Package }
    }

    end {
        # Only query the driver store ourselves when nothing was piped in
        if ($packages.Count -eq 0 -and -not $MyInvocation.ExpectingInput) {
            $packages = @(Get-NvidiaDriverStorePackage)
        }

        $allowed = @('Superseded')
        if ($IncludeUnused) { $allowed += 'Unused' }
        $candidates = @($packages | Where-Object { $_.Status -in $allowed })

        if ($candidates.Count -eq 0) {
            Write-Verbose "No removable driver-store packages found."
            return
        }

        if (-not $WhatIfPreference -and -not (Test-NvidiaCleanerIsElevated)) {
            throw "Removing driver-store packages requires an elevated (Administrator) PowerShell session."
        }

        foreach ($pkg in $candidates) {
            $desc = "$($pkg.OriginalName) $($pkg.DriverVersion) [$($pkg.PublishedName)] ($($pkg.Status), $($pkg.SizeMB) MB)"
            if (-not $PSCmdlet.ShouldProcess($pkg.PublishedName, "Remove driver-store package $desc")) {
                continue
            }

            Write-Host "Removing driver-store package $desc..." -ForegroundColor Cyan
            $output = & "$env:SystemRoot\System32\pnputil.exe" /delete-driver $pkg.PublishedName 2>&1
            $exitCode = $LASTEXITCODE

            $status = if ($exitCode -eq 0) { 'Removed' } else { 'Failed' }
            $message = if ($exitCode -eq 0) { 'Successfully removed.' } else { (($output | Out-String).Trim() -replace '\s+', ' ') }
            if ($exitCode -ne 0) {
                Write-Warning "pnputil could not remove $($pkg.PublishedName): $message"
            }

            [PSCustomObject]@{
                Path          = $pkg.Path
                Category      = 'DriverStore'
                PublishedName = $pkg.PublishedName
                OriginalName  = $pkg.OriginalName
                FreedMB       = if ($exitCode -eq 0) { $pkg.SizeMB } else { 0 }
                Status        = $status
                Message       = $message
            }
        }
    }
}

function Get-NvidiaUpdateCleanupInfo {
    <#
    .SYNOPSIS
        Audits known NVIDIA leftover paths and reports directory locations, file counts, and disk space usage.
    .DESCRIPTION
        Scans common Windows directories where NVIDIA driver installers, GeForce Experience, NVIDIA App,
        and installer services leave behind temporary setup packages, extracted archives, log files, and shader caches.
        Optionally includes superseded driver-store packages, which are usually the largest leftovers of all.
    .PARAMETER IncludeShaderCache
        Switch parameter to include DirectX and OpenGL shader cache locations in the audit.
        Shader caches can be safely cleared, though games will rebuild shaders upon next launch.
    .PARAMETER IncludeDriverStore
        Switch parameter to include superseded NVIDIA driver-store packages in the audit.
        See Get-NvidiaDriverStorePackage for how packages are classified.
    .PARAMETER Category
        Filters the output to specific cleanup categories.
        Valid categories: ExtractedInstaller, InstallerCache, DownloaderCache, TempInstallationFiles,
        ShaderCache, NgxModelCache, ApplicationLogs, DriverStore.
    .EXAMPLE
        Get-NvidiaUpdateCleanupInfo
    .EXAMPLE
        Get-NvidiaUpdateCleanupInfo -IncludeShaderCache -IncludeDriverStore
    .EXAMPLE
        Get-NvidiaUpdateCleanupInfo -Category DownloaderCache, ExtractedInstaller
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeShaderCache,

        [Parameter()]
        [switch]$IncludeDriverStore,

        [Parameter()]
        [ValidateSet('ExtractedInstaller', 'InstallerCache', 'DownloaderCache', 'TempInstallationFiles', 'ShaderCache', 'NgxModelCache', 'ApplicationLogs', 'DriverStore')]
        [string[]]$Category
    )

    process {
        $targets = @()

        # 1. Extracted Driver Setup Files
        $targets += [PSCustomObject]@{
            Category    = 'ExtractedInstaller'
            Path        = 'C:\NVIDIA'
            Description = 'Default directory where NVIDIA driver setup executables unpack installation files.'
            IsPattern   = $false
        }

        # 2. NVIDIA Installer Package Cache
        $targets += [PSCustomObject]@{
            Category    = 'InstallerCache'
            Path        = 'C:\Program Files\NVIDIA Corporation\Installer2'
            Description = 'Cached package folders saved by NVIDIA Installer for rollbacks or component updates.'
            IsPattern   = $false
        }
        if ($env:LOCALAPPDATA) {
            $targets += [PSCustomObject]@{
                Category    = 'InstallerCache'
                Path        = Join-Path $env:LOCALAPPDATA 'NVIDIA Corporation\GeforceNowInstallerFiles'
                Description = 'Extracted GeForce NOW installer payload left behind after setup. The installed app lives in the sibling GeForceNOW folder.'
                IsPattern   = $false
            }
        }

        # 3. Downloader and Service Download Caches
        $targets += [PSCustomObject]@{
            Category    = 'DownloaderCache'
            Path        = 'C:\ProgramData\NVIDIA Corporation\Downloader'
            Description = 'Downloaded driver setup packages and extracted installers saved by GeForce Experience / NVIDIA App.'
            IsPattern   = $false
        }
        $targets += [PSCustomObject]@{
            Category    = 'DownloaderCache'
            Path        = 'C:\ProgramData\NVIDIA Corporation\NetService'
            Description = 'Background setup packages downloaded by NVIDIA Update / NetService.'
            IsPattern   = $false
        }
        $targets += [PSCustomObject]@{
            Category    = 'DownloaderCache'
            Path        = 'C:\ProgramData\NVIDIA Corporation\NVIDIA app\UpdateFramework\ota-artifacts'
            Description = 'Over-The-Air (OTA) downloaded driver packages and extracted setup artifacts saved by NVIDIA App.'
            IsPattern   = $false
        }

        # 4. Temp Installation Folders in %TEMP%
        $tempPath = [System.IO.Path]::GetTempPath()
        $tempPatterns = @('CUDA*', 'NVIDIA*', 'NV_*', 'NVI2_*')
        foreach ($pattern in $tempPatterns) {
            $targets += [PSCustomObject]@{
                Category    = 'TempInstallationFiles'
                Path        = Join-Path $tempPath $pattern
                Description = "Temporary extracted installation files matching pattern '$pattern' in user Temp folder."
                IsPattern   = $true
            }
        }

        # 5. Application Log Files
        $targets += [PSCustomObject]@{
            Category    = 'ApplicationLogs'
            Path        = 'C:\ProgramData\NVIDIA Corporation\NVIDIA app\Logs'
            Description = 'Rotated diagnostic log files generated by NVIDIA App background services.'
            IsPattern   = $false
        }
        $targets += [PSCustomObject]@{
            Category    = 'ApplicationLogs'
            Path        = 'C:\ProgramData\NVIDIA Corporation\NVIDIA app\SessionLogs'
            Description = 'Session diagnostic log files generated by NVIDIA App.'
            IsPattern   = $false
        }

        # 6. Shader Caches (Included if requested or if ShaderCache category filter is specified)
        if ($IncludeShaderCache -or ($Category -and 'ShaderCache' -in $Category)) {
            $localAppData = $env:LOCALAPPDATA
            if ($localAppData) {
                $targets += [PSCustomObject]@{
                    Category    = 'ShaderCache'
                    Path        = Join-Path $localAppData 'NVIDIA\DXCache'
                    Description = 'DirectX shader cache compiled for games and GPU applications.'
                    IsPattern   = $false
                }
                $targets += [PSCustomObject]@{
                    Category    = 'ShaderCache'
                    Path        = Join-Path $localAppData 'NVIDIA\GLCache'
                    Description = 'OpenGL shader cache compiled for games and GPU applications.'
                    IsPattern   = $false
                }
                $targets += [PSCustomObject]@{
                    Category    = 'ShaderCache'
                    Path        = Join-Path $localAppData 'NVIDIA Corporation\NV_Cache'
                    Description = 'Legacy NVIDIA shader cache directory.'
                    IsPattern   = $false
                }
            }
        }

        # 7. NGX / DLSS model cache (opt-in alongside shader caches; regenerates on demand)
        if ($IncludeShaderCache -or ($Category -and 'NgxModelCache' -in $Category)) {
            $targets += [PSCustomObject]@{
                Category    = 'NgxModelCache'
                Path        = 'C:\ProgramData\NVIDIA\NGX\models'
                Description = 'Downloaded DLSS / NGX model snapshots. Re-downloaded on demand by the driver.'
                IsPattern   = $false
            }
        }

        # Filter targets by requested Category parameter if provided
        if ($Category) {
            $targets = $targets | Where-Object { $_.Category -in $Category }
        }

        $results = @()

        # 8. Superseded driver-store packages (opt-in; removal goes through pnputil, not Remove-Item)
        if ($IncludeDriverStore -or ($Category -and 'DriverStore' -in $Category)) {
            $superseded = Get-NvidiaDriverStorePackage -Status Superseded
            foreach ($pkg in $superseded) {
                $dateText = if ($pkg.DriverDate) { $pkg.DriverDate.ToString('yyyy-MM-dd') } else { 'unknown date' }
                $results += [PSCustomObject]@{
                    Category      = 'DriverStore'
                    Path          = $pkg.Path
                    FileCount     = $pkg.FileCount
                    SizeMB        = $pkg.SizeMB
                    Description   = "Superseded driver-store package $($pkg.OriginalName) $($pkg.DriverVersion) ($dateText). No device is bound to it."
                    PublishedName = $pkg.PublishedName
                }
            }
        }

        foreach ($target in $targets) {
            $resolvedPaths = @()

            if ($target.IsPattern) {
                $matchingItems = Get-Item -Path $target.Path -ErrorAction SilentlyContinue
                foreach ($item in $matchingItems) {
                    $resolvedPaths += $item.FullName
                }
            } else {
                if (Test-Path -Path $target.Path) {
                    $resolvedPaths += $target.Path
                }
            }

            foreach ($p in $resolvedPaths) {
                $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue
                if ($files -and $files.Count -gt 0) {
                    $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
                    $sizeMB = [math]::Round(($totalBytes / 1MB), 2)

                    $results += [PSCustomObject]@{
                        Category    = $target.Category
                        Path        = $p
                        FileCount   = $files.Count
                        SizeMB      = $sizeMB
                        Description = $target.Description
                    }
                }
            }
        }

        return $results
    }
}

function Remove-NvidiaUpdateCleanupItem {
    <#
    .SYNOPSIS
        Deletes leftover NVIDIA update files and directories to free up disk space.
    .DESCRIPTION
        Removes leftover installer files, package caches, downloaded setup executables,
        application logs, temporary installation folders, and optionally shader caches.
        Supports pipeline input from Get-NvidiaUpdateCleanupInfo and standard -WhatIf / -Confirm safety parameters.
    .PARAMETER CleanupItem
        One or more cleanup item objects produced by Get-NvidiaUpdateCleanupInfo.
    .PARAMETER Category
        Specific categories to clean if not piping input from Get-NvidiaUpdateCleanupInfo.
    .PARAMETER IncludeShaderCache
        Switch to include shader caches when running directly without pipeline input.
    .PARAMETER IncludeDriverStore
        Switch to include superseded driver-store packages when running directly without pipeline input.
        Driver-store items are removed with pnputil and require an elevated session.
    .PARAMETER Force
        Forces removal of files even if marked as read-only.
    .EXAMPLE
        Get-NvidiaUpdateCleanupInfo | Remove-NvidiaUpdateCleanupItem -WhatIf
    .EXAMPLE
        Remove-NvidiaUpdateCleanupItem -Category DownloaderCache, ExtractedInstaller
    .EXAMPLE
        Remove-NvidiaUpdateCleanupItem -IncludeShaderCache -IncludeDriverStore
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PSCustomObject]$CleanupItem,

        [Parameter()]
        [ValidateSet('ExtractedInstaller', 'InstallerCache', 'DownloaderCache', 'TempInstallationFiles', 'ShaderCache', 'NgxModelCache', 'ApplicationLogs', 'DriverStore')]
        [string[]]$Category,

        [Parameter()]
        [switch]$IncludeShaderCache,

        [Parameter()]
        [switch]$IncludeDriverStore,

        [Parameter()]
        [switch]$Force
    )

    begin {
        $itemsToProcess = @()
    }

    process {
        if ($CleanupItem) {
            $itemsToProcess += $CleanupItem
        }
    }

    end {
        # If nothing was piped in, query items directly. An upstream audit that found nothing
        # must not turn into a full default cleanup.
        if ($itemsToProcess.Count -eq 0 -and -not $MyInvocation.ExpectingInput) {
            $queryParams = @{}
            if ($Category) { $queryParams['Category'] = $Category }
            if ($IncludeShaderCache) { $queryParams['IncludeShaderCache'] = $true }
            if ($IncludeDriverStore) { $queryParams['IncludeDriverStore'] = $true }

            $itemsToProcess = Get-NvidiaUpdateCleanupInfo @queryParams
        }

        if ($itemsToProcess.Count -eq 0) {
            Write-Verbose "No leftover NVIDIA files found to clean."
            return
        }

        # Driver-store packages cannot be deleted with Remove-Item; hand them to pnputil.
        $driverStoreItems = @($itemsToProcess | Where-Object { $_.Category -eq 'DriverStore' -and $_.PublishedName })
        if ($driverStoreItems.Count -gt 0) {
            $packages = Get-NvidiaDriverStorePackage
            $selected = @($packages | Where-Object { $_.PublishedName -in $driverStoreItems.PublishedName })
            $selected | Remove-NvidiaDriverStorePackage
            $itemsToProcess = @($itemsToProcess | Where-Object { $_.Category -ne 'DriverStore' })
        }

        foreach ($item in $itemsToProcess) {
            $targetPath = $item.Path
            if (-not $targetPath -or -not (Test-Path -Path $targetPath)) {
                continue
            }

            $targetDesc = "$($item.Category) at '$targetPath' ($($item.FileCount) files, $($item.SizeMB) MB)"

            if ($PSCmdlet.ShouldProcess($targetPath, "Remove $targetDesc")) {
                Write-Host "Cleaning $($item.Category): '$targetPath' ($($item.SizeMB) MB)..." -ForegroundColor Cyan

                $status = 'Removed'
                $message = 'Successfully removed.'
                $freedMB = $item.SizeMB

                try {
                    Remove-Item -Path $targetPath -Recurse -Force:$Force -ErrorAction Stop
                } catch {
                    # Attempt item-by-item cleanup if root folder removal had locked files
                    $subItems = Get-ChildItem -Path $targetPath -ErrorAction SilentlyContinue
                    $removedCount = 0
                    $failedCount = 0

                    foreach ($sub in $subItems) {
                        try {
                            Remove-Item -Path $sub.FullName -Recurse -Force:$Force -ErrorAction Stop
                            $removedCount++
                        } catch {
                            $failedCount++
                        }
                    }

                    if ($failedCount -eq 0) {
                        $status = 'Removed'
                        $message = 'Successfully removed sub-contents.'
                    } elseif ($removedCount -gt 0) {
                        $status = 'PartiallyRemoved'
                        $message = "Removed $removedCount items, $failedCount items locked or restricted."
                    } else {
                        $status = 'Failed'
                        $message = "Failed to remove: $_"
                        Write-Warning "Could not remove '$targetPath': $_"
                    }
                }

                [PSCustomObject]@{
                    Path      = $targetPath
                    Category  = $item.Category
                    FreedMB   = $freedMB
                    Status    = $status
                    Message   = $message
                }
            }
        }
    }
}

Export-ModuleMember -Function Get-NvidiaUpdateCleanupInfo, Remove-NvidiaUpdateCleanupItem, Get-NvidiaDriverStorePackage, Remove-NvidiaDriverStorePackage -Alias Get-NvidiaCleanupInfo, Remove-NvidiaCleanupItem
