# RoutineDiskCleanup

A PowerShell module that collects the easy disk space wins on a Windows machine into one audit-and-clean workflow you can run by hand or on a weekly schedule.

Everything it touches is regenerable: temp files, crash reports, package manager download caches, GPU shader caches, browser and editor caches, game launcher update leftovers and logs, and Windows Update leftovers. Nothing it clears is user data, with the single exception of the Recycle Bin, which is opt-in.

---

## Why This Exists

Caches grow silently and nobody clears them. On a developer machine with a few package managers and a GPU, it's normal to find 20 to 40 GB of caches that would be rebuilt in minutes. Windows' own Storage Sense handles temp files and the Recycle Bin, but knows nothing about npm, pip, uv, Scoop, Cargo, conda, NuGet, or shader caches.

---

## Installation & Importing

```powershell
Import-Module .\RoutineDiskCleanup\RoutineDiskCleanup.psd1 -Force
```

To make it permanently available, copy the `RoutineDiskCleanup` folder to a location in `$env:PSModulePath`.

---

## Cmdlets & Usage Guide

### 1. `Get-RoutineDiskCleanupInfo`

Audits every known location and reports the size and file count. Deletes nothing.

```powershell
# Default categories (the always-safe set)
Get-RoutineDiskCleanupInfo

# Everything, biggest first
Get-RoutineDiskCleanupInfo -IncludeAll | Sort-Object SizeMB -Descending | Format-Table Category, SizeMB, FileCount, Path

# Only count files untouched for a week
Get-RoutineDiskCleanupInfo -Category PackageCache, ShaderCache -MinimumAgeDays 7
```

### 2. `Invoke-RoutineDiskCleanup`

Clears what the audit found. Deletes folder *contents*, never the folders themselves, skips anything locked or newer than the age cutoff, and prunes empty subfolders afterward. Supports `-WhatIf` and `-Confirm`.

```powershell
# Dry run
Get-RoutineDiskCleanupInfo | Invoke-RoutineDiskCleanup -WhatIf

# Interactive: prompts per location
Invoke-RoutineDiskCleanup

# Non-interactive, default categories
Invoke-RoutineDiskCleanup -Confirm:$false

# Specific categories with per-location results
Invoke-RoutineDiskCleanup -Category BrowserCache, EditorCache -PassThru
```

Locations that need elevation are skipped with a warning in an unelevated session, so a normal-user run still does everything it can.

### Cleaning every account on a shared PC: `-AllUsers`

By default, per-user caches (temp, crash dumps, package, shader, browser, editor, and launcher caches) are only cleaned for the account running the command. On a family or shared PC, the other accounts' caches pile up untouched; a single shader cache in another profile can hold several GB. Add `-AllUsers` from an elevated session to include every user profile:

```powershell
# Elevated: see every account's caches
Get-RoutineDiskCleanupInfo -AllUsers | Format-Table User, Category, SizeMB, Path

# Clean them
Invoke-RoutineDiskCleanup -AllUsers -Confirm:$false

# Schedule it (needs -RunElevated)
Register-RoutineDiskCleanupTask -AllUsers -RunElevated
```

Every result carries a `User` column (`(system)` for machine-wide locations). Only real user accounts are included; service and app-pool profiles are not. Scoop, conda, and the Recycle Bin stay current-user only, since they act through that user's tools. Profiles are assumed to use the default `AppData` layout.

### 3. `Register-RoutineDiskCleanupTask` / `Unregister-RoutineDiskCleanupTask`

Creates a weekly scheduled task under the current user that runs the cleanup non-interactively and appends one summary line per run to a log.

```powershell
# Sunday 03:00, default categories, files older than 7 days, log in %LOCALAPPDATA%\RoutineDiskCleanup
Register-RoutineDiskCleanupTask

# Custom schedule and categories, allowed to clean system locations (register from an elevated session)
Register-RoutineDiskCleanupTask -Category TempFiles, CrashReports, PackageCache, ShaderCache -DayOfWeek Saturday -At '04:30' -RunElevated

# Remove it
Unregister-RoutineDiskCleanupTask
```

The task is registered with wake-to-run **off**, so it never wakes a sleeping PC.

---

## Categories

| Category | Default? | What it clears | Notes |
| :--- | :---: | :--- | :--- |
| **TempFiles** | Yes | `%LOCALAPPDATA%\Temp`, `C:\Windows\Temp` | Files touched in the last 24 hours are always left alone. System temp needs elevation. |
| **CrashReports** | Yes | CrashDumps, WER report queues and archives, Minidump, LiveKernelReports | System locations need elevation. |
| **PackageCache** | Yes | npm, pip, uv, Scoop download cache, `scoop cleanup *`, Cargo `.crate` cache, Go build cache, Yarn, NuGet HTTP cache, `conda clean --all` | Pure download caches. The next install re-fetches what it needs. `scoop cleanup` removes only app versions that `current` does not point to. conda and Scoop steps only run if installed; conda keeps packages that environments link to. |
| **DevDependencyCache** | No | NuGet global packages, extracted Cargo sources, Gradle caches | Safe, but the next restore or build is noticeably slower. |
| **ShaderCache** | Yes | NVIDIA DXCache/GLCache, AMD DxCache, Intel ShaderCache, D3DSCache, Steam `steamapps\shadercache` | Games rebuild shaders on next launch; expect brief stutter once. Overlaps with NvidiaUpdateCleaner's ShaderCache category. |
| **BrowserCache** | No | Cache, Code Cache, GPUCache for every Chrome, Edge, and Brave profile | Close the browser first. Locked files are skipped. Does not touch history, cookies, or logins. |
| **EditorCache** | No | VS Code Cache, CachedData, CachedExtensionVSIXs | Close VS Code first. |
| **GameLauncher** | Yes | Old Ubisoft Connect self-update builds in `ProgramData\Ubisoft\Ubisoft Game Launcher\patch`; Steam logs, dumps, and `htmlcache`; Epic Games Launcher logs and `webcache` | Ubisoft keeps one ~575 MB build folder per launcher update and never prunes them, so this grows by several GB a year. The build named in `patch.txt` and the newest build are always kept, nothing is removed if `patch.txt` can't be read, and the step is skipped while Ubisoft Connect is running. Close Steam and Epic for a full browser-cache clear; locked files are skipped. |
| **WindowsUpdate** | Partly | Delivery Optimization cache (default); `SoftwareDistribution\Download` (opt-in) | Needs elevation. The SoftwareDistribution step stops and restarts the Windows Update and BITS services. |
| **ComponentStore** | No | `DISM /Online /Cleanup-Image /StartComponentCleanup` | Needs elevation and takes minutes. Windows runs the same cleanup itself after a 30-day grace; this skips the wait. Pass `-ResetBase` to `Invoke-RoutineDiskCleanup` for the aggressive form (see below). |
| **RecycleBin** | No | Empties the Recycle Bin on all drives | Opt-in because it is the one thing here that is technically user data. |

### About `/ResetBase`

`Invoke-RoutineDiskCleanup -Category ComponentStore -ResetBase` adds `/ResetBase` to the DISM call. That permanently deletes every superseded component, which frees the most space but means **installed updates can no longer be uninstalled**. It's a fine thing to do by hand after a stable month, and a poor thing to do on a schedule, so the scheduler never sets it. Don't run it while an update is pending a restart.

---

## Safety & Permissions

- **Nothing here is user data.** Every default location is a cache that the owning program rebuilds on demand.
- **Locked files are skipped, not forced.** A browser or build that is running keeps its files.
- **Folders are never deleted**, only their contents, so programs that expect their cache folder to exist are not surprised.
- **Junctions and symlinks are never followed.** A cache folder that is actually a link to somewhere else is not traversed.
- **Elevation** is needed for system temp, system crash reports, the Windows Update categories, ComponentStore, and other users' profiles under `-AllUsers`. Everything else runs as a normal user.
- **Dry-run first.** `Get-RoutineDiskCleanupInfo | Invoke-RoutineDiskCleanup -WhatIf` shows exactly what would be cleared.
