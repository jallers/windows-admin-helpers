@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'RoutineDiskCleanup.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PowerShell Host Name
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'e7c2a9d4-5b31-4f8e-9a6d-2c1f0b7d8e93'

    # Author of this module
    Author = 'Jim Allers'

    # Company or vendor of this module
    CompanyName = 'Windows Admin Helpers'

    # Copyright statement for this module
    Copyright = '(c) 2026 Jim Allers. MIT License.'

    # Description of the functionality provided by this module
    Description = 'Audits and clears the easy, regenerable disk space wins on Windows (temp files, crash reports, package manager caches, shader caches, browser caches, update leftovers) by hand or on a weekly schedule.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell platform required by this module
    ProcessorArchitecture = 'None'

    # Functions to export from this module, for best performance
    FunctionsToExport = @('Get-RoutineDiskCleanupInfo', 'Invoke-RoutineDiskCleanup', 'Register-RoutineDiskCleanupTask', 'Unregister-RoutineDiskCleanupTask')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('Cleanup', 'DiskCleaner', 'Cache', 'SysAdmin', 'Maintenance')
        }
    }
}
