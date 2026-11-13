@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'UninstallHelper.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PowerShell Host Name
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = '9e0b12e6-a052-4752-bfbc-cc9804b38d72'

    # Author of this module
    Author = 'Jim Allers'

    # Copyright statement for this module
    Copyright = '(c) 2026 Jim Allers. MIT License.'

    # Description of the functionality provided by this module
    Description = 'Helps audit and manually clean up Windows applications when their uninstallers are broken or missing.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell platform required by this module
    ProcessorArchitecture = 'None'

    # Functions to export from this module, for best performance
    FunctionsToExport = @('Get-InstalledApp', 'Get-AppCleanupInfo', 'Export-UninstallKey', 'Remove-InstalledAppRegistryKey')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('Uninstall', 'Registry', 'Cleanup', 'SysAdmin')
        }
    }
}
