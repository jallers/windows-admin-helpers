# Windows Admin Helpers

Small PowerShell modules for keeping a Windows machine tidy. Each one is self-contained, with its own README.

| Module | What it does |
|---|---|
| [NvidiaUpdateCleaner](NvidiaUpdateCleaner/README.md) | Audits and cleans up files that NVIDIA driver updates, GeForce Experience, and the NVIDIA App leave behind |
| [RoutineDiskCleanup](RoutineDiskCleanup/README.md) | Clears the easy, regenerable disk space wins (temp files, package manager caches, shader caches, Windows Update leftovers) in one audit-and-clean pass you can run by hand or on a weekly schedule |
| [UninstallHelper](UninstallHelper/README.md) | Audits and manually cleans up apps whose uninstallers are missing or broken, and backs up registry keys before removing them |

## Usage

```powershell
Import-Module .\RoutineDiskCleanup\RoutineDiskCleanup.psd1
Get-Command -Module RoutineDiskCleanup
```

See each module's README for its commands and safety notes.
