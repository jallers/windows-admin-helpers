# Windows Admin Helpers

Small PowerShell modules for keeping a Windows machine tidy. Each one is self-contained, with its own README.

| Module | What it does |
|---|---|
| [NvidiaUpdateCleaner](NvidiaUpdateCleaner/README.md) | Audits and cleans up files that NVIDIA driver updates, GeForce Experience, and the NVIDIA App leave behind |
| [RoutineDiskCleanup](RoutineDiskCleanup/README.md) | Clears the easy, regenerable disk space wins (temp files, package manager caches, shader caches, game launcher leftovers, Windows Update leftovers) in one audit-and-clean pass you can run by hand or on a weekly schedule |
| [UninstallHelper](UninstallHelper/README.md) | Audits and manually cleans up apps whose uninstallers are missing or broken, and backs up registry keys before removing them |

## Usage

```powershell
Import-Module .\RoutineDiskCleanup\RoutineDiskCleanup.psd1
Get-Command -Module RoutineDiskCleanup
```

See each module's README for its commands and safety notes.

## Disk space report

`Get-DiskSpaceReport.ps1` is a read-only report of where the space on the system drive went and what can be reclaimed. It runs the module audits plus checks that only make sense elevated: Windows upgrade leftovers, hibernation and page files, restore points, older driver-store packages, orphaned Windows Installer files, installed Steam games with last-played dates and untracked copies, and the largest folders and files across every user profile. It deletes nothing.

```powershell
# From an elevated PowerShell
powershell -ExecutionPolicy Bypass -File .\Get-DiskSpaceReport.ps1
```
