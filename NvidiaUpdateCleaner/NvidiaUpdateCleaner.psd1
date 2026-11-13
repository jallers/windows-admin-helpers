@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'NvidiaUpdateCleaner.psm1'

    # Version number of this module.
    ModuleVersion = '1.1.0'

    # Supported PowerShell Host Name
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'b3d8e841-4702-4c6e-9821-4f9e1e23a456'

    # Author of this module
    Author = 'Jim Allers'

    # Copyright statement for this module
    Copyright = '(c) 2026 Jim Allers. MIT License.'

    # Description of the functionality provided by this module
    Description = 'Audits and cleans up residual setup files, installer caches, download leftovers, shader and DLSS caches, and superseded driver-store packages from NVIDIA driver and software updates.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell platform required by this module
    ProcessorArchitecture = 'None'

    # Functions to export from this module, for best performance
    FunctionsToExport = @('Get-NvidiaUpdateCleanupInfo', 'Remove-NvidiaUpdateCleanupItem', 'Get-NvidiaDriverStorePackage', 'Remove-NvidiaDriverStorePackage')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @('Get-NvidiaCleanupInfo', 'Remove-NvidiaCleanupItem')

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('NVIDIA', 'Driver', 'Cleanup', 'SysAdmin', 'DiskCleaner')
        }
    }
}
