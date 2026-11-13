# UninstallHelper

A lightweight PowerShell module designed to help system administrators audit, analyze, and manually clean up Windows applications when their original uninstaller files are missing, corrupted, or cannot be found.

## Features

- **Get-InstalledApp**: Lists programs from the Windows "Add or Remove Programs" registry paths (`HKLM` 64-bit, `HKLM` 32-bit/Wow6432Node, and `HKCU`). Allows filtering by `DisplayName` with wildcards.
- **Get-AppCleanupInfo**: Analyzes an installed application and outputs a detailed list of related folders and registry paths that you should inspect or clean up manually.
	- **Export-UninstallKey**: Backs up an application's uninstall registry key to a standard `.reg` file inside `UninstallBackups` in the user's home directory so that you can safely restore it if something goes wrong.
- **Remove-InstalledAppRegistryKey**: Deletes the uninstall entry from the registry (removing it from Windows "Add or Remove Programs"), after automatically creating a `.reg` backup in `UninstallBackups`.

---

## Installation & Importing

To import and use the module in your current PowerShell session, navigate to the `admin-helpers` directory and import the module manifest:

```powershell
Import-Module .\UninstallHelper\UninstallHelper.psd1 -Force
```

To make the module permanently available across all PowerShell sessions, copy the `UninstallHelper` folder to one of your `$env:PSModulePath` folders (e.g., `Documents\WindowsPowerShell\Modules` or `Documents\PowerShell\Modules`).

---

## Usage Guide

### 1. Find an Installed Application
Use `Get-InstalledApp` to search for applications. It supports wildcard searches on the Display Name:

```powershell
# List all apps matching "Python"
Get-InstalledApp -DisplayName "*Python*"

# List all 32-bit apps on a 64-bit machine
Get-InstalledApp -Scope Machine32
```

### 2. Identify Manual Cleanup Paths
When an app's uninstaller is broken, use `Get-AppCleanupInfo` to identify where its files and keys might reside:

```powershell
# Get a cleanup analysis report
Get-InstalledApp -DisplayName "*SomeBrokenApp*" | Get-AppCleanupInfo
```

This returns a custom object containing:
- **DirectoriesToInspect**: Common installation locations (Program Files, AppData, ProgramData) matched against the App Name and Publisher.
- **RegistryKeysToInspect**: Machine and user-specific registry keys under `SOFTWARE\Publisher\AppName` or `SOFTWARE\AppName`.
- **UninstallRegistryPath**: The direct key for the uninstaller itself.

### 3. Back Up an Uninstall Registry Key
Before modifying anything, always back up the registry entry:

```powershell
# Back up to your home directory under UninstallBackups (default)
Get-InstalledApp -DisplayName "LegacyTool" | Export-UninstallKey

# Back up to a custom folder
Get-InstalledApp -DisplayName "LegacyTool" | Export-UninstallKey -Path "C:\MyBackups"
```

### 4. Remove the Uninstall Entry (Remove from Add or Remove Programs)
To remove the application from Windows' "Add or Remove Programs" list, delete its uninstall registry key. By default, this will automatically back up the key to `UninstallBackups` in your home directory first:

```powershell
# Interactively remove with backup (will prompt for confirmation)
Get-InstalledApp -DisplayName "LegacyTool" | Remove-InstalledAppRegistryKey

# Perform a dry-run to see what would happen
Get-InstalledApp -DisplayName "LegacyTool" | Remove-InstalledAppRegistryKey -WhatIf
```

---

## Safety & Permissions

- **Elevation**: To run `Remove-InstalledAppRegistryKey` on system-wide software (under `HKLM`), you must run PowerShell as **Administrator**.
- **Backups**: Every execution of `Remove-InstalledAppRegistryKey` backs up the registry state to a `.reg` file in your home directory under `UninstallBackups` (unless `-Backup:$false` is explicitly set). Double-clicking this file will restore the registry key instantly.
