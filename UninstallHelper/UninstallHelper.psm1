<#
.Synopsis
    UninstallHelper Module
    Provides utilities to audit, analyze, and manually clean up Windows application installations
    when uninstallers are missing or broken.
#>

function Get-InstalledApp {
    <#
    .SYNOPSIS
        Lists installed applications from the Windows Uninstall registry paths.
    .DESCRIPTION
        Queries HKLM and HKCU registry keys representing the "Add or Remove Programs" list.
        Supports filtering by DisplayName and searching specific registry scopes (64-bit, 32-bit, or user).
    .PARAMETER DisplayName
        A wildcard pattern or exact string to search for in the application's DisplayName.
    .PARAMETER Scope
        Specifies which registry scopes to query.
        Valid values: All, Machine64, Machine32, User. Default is All.
    .EXAMPLE
        Get-InstalledApp -DisplayName "Python"
    .EXAMPLE
        Get-InstalledApp -Scope Machine32
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DisplayName,

        [Parameter()]
        [ValidateSet('All', 'Machine64', 'Machine32', 'User')]
        [string]$Scope = 'All'
    )

    process {
        $paths = @()
        if ($Scope -eq 'All' -or $Scope -eq 'Machine64') {
            $paths += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        }
        if ($Scope -eq 'All' -or $Scope -eq 'Machine32') {
            if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") {
                $paths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            }
        }
        if ($Scope -eq 'All' -or $Scope -eq 'User') {
            $paths += "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        }

        # Retrieve registry keys
        $apps = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -or $_.QuietUninstallString -or $_.UninstallString } |
            Select-Object @{N='DisplayName'; E={$_.DisplayName}},
                          @{N='DisplayVersion'; E={$_.DisplayVersion}},
                          @{N='Publisher'; E={$_.Publisher}},
                          @{N='UninstallString'; E={$_.UninstallString}},
                          @{N='QuietUninstallString'; E={$_.QuietUninstallString}},
                          @{N='InstallLocation'; E={$_.InstallLocation}},
                          @{N='InstallDate'; E={$_.InstallDate}},
                          @{N='PSPath'; E={$_.PSPath}},
                          @{N='RegistryKey'; E={$_.PSChildName}}

        if ($DisplayName) {
            $apps = $apps | Where-Object { $_.DisplayName -like "*$DisplayName*" }
        }

        $apps
    }
}

function Get-AppCleanupInfo {
    <#
    .SYNOPSIS
        Analyzes an installed application and provides potential file and registry locations for manual cleanup.
    .DESCRIPTION
        When an application's uninstaller is missing or corrupt, this cmdlet helps locate associated directories
        (Program Files, AppData, ProgramData) and registry hives based on the application's DisplayName, Publisher,
        and declared InstallLocation.
    .PARAMETER App
        An application object returned by Get-InstalledApp.
    .EXAMPLE
        Get-InstalledApp -DisplayName "MyBrokenApp" | Get-AppCleanupInfo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$App
    )

    process {
        if (-not $App.RegistryKey -or -not $App.PSPath) {
            Write-Error "Input object must be an application object returned by Get-InstalledApp."
            return
        }

        # Suggest directories to check
        $dirsToCheck = @()
        if ($App.InstallLocation -and (Test-Path $App.InstallLocation)) {
            $dirsToCheck += [PSCustomObject]@{
                Path = $App.InstallLocation
                Description = "Declared InstallLocation (Exists)"
            }
        } elseif ($App.InstallLocation) {
            $dirsToCheck += [PSCustomObject]@{
                Path = $App.InstallLocation
                Description = "Declared InstallLocation (Not Found - Check manually)"
            }
        }

        # Derive suggested folders from DisplayName and Publisher
        $cleanName = ""
        if ($App.DisplayName) {
            $cleanName = $App.DisplayName -replace '[\\/:*?"<>|]', ''
        }
        $cleanPublisher = ""
        if ($App.Publisher) {
            $cleanPublisher = $App.Publisher -replace '[\\/:*?"<>|]', ''
        }

        $commonRoots = @(
            [PSCustomObject]@{ Path = $env:ProgramFiles; Name = "Program Files" },
            [PSCustomObject]@{ Path = ${env:ProgramFiles(x86)}; Name = "Program Files (x86)" },
            [PSCustomObject]@{ Path = $env:APPDATA; Name = "Roaming AppData" },
            [PSCustomObject]@{ Path = $env:LOCALAPPDATA; Name = "Local AppData" },
            [PSCustomObject]@{ Path = "C:\ProgramData"; Name = "ProgramData" }
        )

        foreach ($root in $commonRoots) {
            if (-not $root.Path) { continue }
            
            # 1. Search for Root\Publisher\AppName
            if ($cleanPublisher) {
                $pubPath = Join-Path $root.Path $cleanPublisher
                if (Test-Path $pubPath) {
                    if ($cleanName) {
                        $appInPubPath = Join-Path $pubPath $cleanName
                        if (Test-Path $appInPubPath) {
                            $dirsToCheck += [PSCustomObject]@{
                                Path = $appInPubPath
                                Description = "$($root.Name) (Publisher\AppName matches)"
                            }
                        }
                    }
                    $dirsToCheck += [PSCustomObject]@{
                        Path = $pubPath
                        Description = "$($root.Name) (Publisher folder exists)"
                    }
                }
            }

            # 2. Search for Root\AppName directly
            if ($cleanName) {
                $directPath = Join-Path $root.Path $cleanName
                if (Test-Path $directPath) {
                    $dirsToCheck += [PSCustomObject]@{
                        Path = $directPath
                        Description = "$($root.Name) (AppName folder exists)"
                    }
                }
            }
        }

        # Suggest registry keys to check
        $keysToCheck = @()
        # Add the uninstall key itself
        $keysToCheck += [PSCustomObject]@{
            RegistryPath = $App.PSPath
            Description = "The application's Uninstall Registry Key"
        }

        # Derive potential Software keys
        if ($cleanPublisher) {
            $keysToCheck += [PSCustomObject]@{
                RegistryPath = "HKLM:\SOFTWARE\$cleanPublisher"
                Description = "Potential machine-wide publisher software key"
            }
            $keysToCheck += [PSCustomObject]@{
                RegistryPath = "HKCU:\SOFTWARE\$cleanPublisher"
                Description = "Potential user-specific publisher software key"
            }
            if ($cleanName) {
                $keysToCheck += [PSCustomObject]@{
                    RegistryPath = "HKLM:\SOFTWARE\$cleanPublisher\$cleanName"
                    Description = "Potential machine-wide app software key"
                }
                $keysToCheck += [PSCustomObject]@{
                    RegistryPath = "HKCU:\SOFTWARE\$cleanPublisher\$cleanName"
                    Description = "Potential user-specific app software key"
                }
            }
        }
        if ($cleanName) {
            $keysToCheck += [PSCustomObject]@{
                RegistryPath = "HKLM:\SOFTWARE\$cleanName"
                Description = "Potential machine-wide app software key (direct)"
            }
            $keysToCheck += [PSCustomObject]@{
                RegistryPath = "HKCU:\SOFTWARE\$cleanName"
                Description = "Potential user-specific app software key (direct)"
            }
        }

        # Clean duplicates
        $dirsToCheck = $dirsToCheck | Sort-Object -Property Path -Unique
        $keysToCheck = $keysToCheck | Sort-Object -Property RegistryPath -Unique

        # Return a structured custom object
        [PSCustomObject]@{
            AppName = $App.DisplayName
            Publisher = $App.Publisher
            Version = $App.DisplayVersion
            UninstallRegistryPath = $App.PSPath
            InstallLocation = $App.InstallLocation
            UninstallString = $App.UninstallString
            DirectoriesToInspect = $dirsToCheck
            RegistryKeysToInspect = $keysToCheck
        }
    }
}

function Export-UninstallKey {
    <#
    .SYNOPSIS
        Exports the registry uninstall key of an application to a .reg file for backup.
    .DESCRIPTION
        Converts the application's registry path to standard registry formatting and exports
        the key using reg.exe.
    .PARAMETER App
        An application object returned by Get-InstalledApp.
    .PARAMETER Path
        The directory where the backup .reg file should be saved. Defaults to a folder in the user's home directory (e.g., C:\Users\Username\UninstallBackups).
    .EXAMPLE
        Get-InstalledApp -DisplayName "LegacyTool" | Export-UninstallKey
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$App,

        [Parameter(Position = 1)]
        [string]$Path = (Join-Path $env:USERPROFILE "UninstallBackups")
    )

    process {
        if (-not $App.PSPath) {
            Write-Error "Input object must be an application object returned by Get-InstalledApp."
            return
        }

        # Convert PowerShell path to standard registry path for reg.exe
        # PSPath: Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}
        # Or: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}
        $rawPath = $App.PSPath
        $regPath = ""
        if ($rawPath -match 'Registry::(.*)') {
            $regPath = $Matches[1]
        } elseif ($rawPath -match '^HKLM:\\(.*)') {
            $regPath = "HKEY_LOCAL_MACHINE\" + $Matches[1]
        } elseif ($rawPath -match '^HKCU:\\(.*)') {
            $regPath = "HKEY_CURRENT_USER\" + $Matches[1]
        } else {
            $regPath = $rawPath
        }

        # Ensure destination directory exists
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }

        $safeName = ""
        if ($App.DisplayName) {
            $safeName = ($App.DisplayName -replace '[\\/:*?"<>|]', '') -replace '\s+', '_'
        }
        if (-not $safeName) { $safeName = $App.RegistryKey }
        $fileName = "Backup_$($safeName)_Uninstall.reg"
        $fullPath = Join-Path $Path $fileName

        Write-Verbose "Exporting registry key '$regPath' to '$fullPath'..."
        
        # Call reg.exe export
        & reg.exe export $regPath $fullPath /y | Out-Null

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Registry key successfully backed up to: $fullPath" -ForegroundColor Green
            return $fullPath
        } else {
            Write-Error "Failed to export registry key. reg.exe exited with code $LASTEXITCODE."
            return $null
        }
    }
}

function Remove-InstalledAppRegistryKey {
    <#
    .SYNOPSIS
        Removes the uninstall registry key of an application, backing it up first.
    .DESCRIPTION
        Performs manual registry cleanup by backing up the selected app's uninstall key to a .reg file
        and then deleting the key from the registry path. Supports -WhatIf and -Confirm.
    .PARAMETER App
        An application object returned by Get-InstalledApp.
    .PARAMETER Backup
        If true, exports the key to a .reg file before deletion. Default is true.
    .PARAMETER BackupFolder
        The directory where the backup .reg file should be saved. Defaults to a folder in the user's home directory (e.g., C:\Users\Username\UninstallBackups).
    .EXAMPLE
        Get-InstalledApp -DisplayName "BrokenApp" | Remove-InstalledAppRegistryKey
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$App,

        [Parameter()]
        [switch]$Backup = $true,

        [Parameter()]
        [string]$BackupFolder = (Join-Path $env:USERPROFILE "UninstallBackups")
    )

    process {
        if (-not $App.PSPath) {
            Write-Error "Input object must be an application object returned by Get-InstalledApp."
            return
        }

        if ($Backup) {
            $backupFile = Export-UninstallKey -App $App -Path $BackupFolder
            if (-not $backupFile) {
                Write-Warning "Skipping registry key removal because backup failed. Use -Backup:`$false to force removal without backup."
                return
            }
        }

        if ($PSCmdlet.ShouldProcess($App.DisplayName, "Remove Uninstall Registry Key from $($App.PSPath)")) {
            Remove-Item -Path $App.PSPath -Recurse -Force
            Write-Host "Successfully removed registry key: $($App.PSPath)" -ForegroundColor Green
        }
    }
}

# Export functions
Export-ModuleMember -Function Get-InstalledApp, Get-AppCleanupInfo, Export-UninstallKey, Remove-InstalledAppRegistryKey
