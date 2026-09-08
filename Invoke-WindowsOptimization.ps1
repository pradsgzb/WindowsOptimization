#requires -version 5.1
#requires -PSEdition Desktop

<#
.SYNOPSIS
    Audits and safely optimizes supported Windows 10/11 performance settings.

.DESCRIPTION
    WinOptimize is a conservative Windows client optimization tool. It provides:
      * Explicit Y/N/A consent, scoped to the current category.
      * One confirmation per temporary folder, never one prompt per file.
      * Granular categories, operation IDs, service names, and convenience switches.
      * WhatIf support, structured backups, detailed logs, progress, and rollback.
      * An explicit service allowlist and a hard denylist for critical services.
      * Supported Microsoft maintenance and configuration interfaces only.

    The default mode is Audit and makes no operating-system configuration changes.
    No script can guarantee a performance increase. Measure before and after.

.PARAMETER Mode
    Audit (default) collects a JSON snapshot and changes no Windows setting. Apply
    evaluates only explicitly selected operations. Restore replays authenticated,
    reversible records from a prior Apply manifest in reverse order.

.PARAMETER Category
    Select one or more categories: Cleanup, Storage, Network, Power, Services,
    UserExperience, or Startup. In Apply, Services selects only bulk-eligible
    allowlisted services; use -ServiceName for individually gated services.

.PARAMETER IncludeOptimization
    Select exact operation IDs. Use -ListOptimizations to discover IDs.

.PARAMETER ExcludeOptimization
    Exclude exact operation IDs from the combined Apply/Audit selection.

.PARAMETER RestoreOptimization
    In Restore mode, limit restore to exact reversible operation IDs present in the
    authenticated manifest. Apply selectors are invalid in Restore mode.

.PARAMETER ServiceName
    Select exact service names from the script's allowlist. Unknown and critical
    service names are rejected case-insensitively. Each selected service still has
    its own consent decision unless an applicable automatic policy is chosen.

.PARAMETER AdapterInterfaceGuid
    Restrict RSS audit/apply to one or more exact adapter interface GUIDs. Only
    physical, wired, RSS-capable adapters are eligible.

.PARAMETER VolumeDriveLetter
    Restrict volume audit/optimization to drive letters such as C or D:. Only
    healthy, fixed NTFS/ReFS volumes are eligible.

.PARAMETER ConsentPolicy
    Ask displays Y/N/A for each applicable operation. A means all remaining items
    at the same risk level in that category only. Recommended automatically approves
    only operations marked recommended and is valid only for Apply. YesToAll and
    NoToAll are explicit unattended policies. Restore accepts Ask, YesToAll, or
    NoToAll; Recommended is rejected because Apply recommendations do not describe
    restore decisions.

.PARAMETER MinimumAgeDays
    Only temporary files last modified at least this many days ago are eligible.
    Default: 7. Folders are always preserved. Zero additionally requires
    -AcknowledgeDeleteAllTempAges.

.PARAMETER BackupPath
    Apply: optional new file path for the authenticated rollback manifest. Restore:
    required manifest path. It must be inside the protected WinOptimize data root;
    existing primary or .previous files are never overwritten by a new Apply.
    Retain the companion protected key under the same WinOptimize data root.

.PARAMETER LogDirectory
    Optional log directory inside the protected WinOptimize data root. The default
    is its Logs child. External paths and reparse-point paths are refused.

.PARAMETER ReportPath
    Optional new Audit JSON path inside the protected WinOptimize data root. Existing
    files are not overwritten. Valid only in Audit mode.

.PARAMETER AllRecommended
    Select every operation marked recommended. The conservative 1.0 catalog normally
    recommends only aged current-user Temp cleanup; no service is recommended.

.PARAMETER CleanUserTemp
    Select the canonical signed-in user's LocalAppData\Temp folder. One folder-level
    Y/N/A prompt is shown; individual files are never prompted. Service/Session-0
    accounts are refused.

.PARAMETER CleanWindowsTemp
    Select the canonical Windows\Temp folder. This is a separate medium-risk,
    folder-level decision. If both canonical roots coincide, the stricter Windows
    Temp operation is used.

.PARAMETER ClearDeliveryOptimizationCache
    Use Microsoft's Delivery Optimization cmdlet to delete unpinned cached content.
    Windows may download it again; this is a disk-space action, not a guaranteed boost.

.PARAMETER RunComponentCleanup
    Analyze the component store, then run DISM StartComponentCleanup. ResetBase is
    never used. The action is opt-in, irreversible by this script, and maintenance
    state is rechecked immediately before launch.

.PARAMETER OptimizeFixedVolumes
    Ask once per eligible volume, then let Optimize-Volume choose its media-aware
    default. The script never forces HDD defragmentation onto SSDs.

.PARAMETER NormalizeTcpAutoTuning
    Set only eligible local InternetCustom/DatacenterCustom TCP templates back to
    Normal. Group Policy is never overridden. Every change requires explicit network
    interruption acknowledgement; remote changes also require the remote override.

.PARAMETER EnableReceiveSideScaling
    Enable RSS only on explicitly eligible physical wired adapters where it is off.
    Consent is per adapter. Adapter interruption is possible.

.PARAMETER SetBestPerformancePowerMode
    Windows 11: set the current user's documented AC power-mode vote to Best
    Performance. Windows 10: activate the built-in High performance plan only if it
    already exists; that plan's configured AC and battery/DC values then apply. No
    plan is created, and Windows 11 battery/DC power mode is not changed.

.PARAMETER DisableClientAnimations
    Disable only the current user's client-area animations through the supported
    SystemParametersInfo API. The exact prior Boolean value is restorable.

.PARAMETER ReviewStartupApps
    Open the supported Startup Apps settings page after consent. No startup entry is
    disabled automatically.

.PARAMETER ReviewStorageSense
    Open Storage Sense settings after consent. Downloads and cloud-content policies
    are not changed automatically.

.PARAMETER DisableOptionalServices
    Select the conservative bulk-eligible service subset. No service is recommended;
    with Ask, each service receives its own Y/N/A prompt. Medium/sensitive services
    remain explicitly selectable only by -ServiceName or an exact
    -IncludeOptimization operation ID.

.PARAMETER DisableDemandStartServices
    Permit an explicitly selected Manual-and-Stopped allowlisted service to be set
    Disabled. Without this switch, such a service is left alone because it has no
    active CPU cost and may be trigger-started later.

.PARAMETER SkipRestorePoint
    Do not attempt the best-effort System Restore checkpoint before reversible Apply
    changes. The authenticated per-operation rollback manifest is still mandatory.

.PARAMETER AcknowledgeIrreversibleActions
    Required when Recommended or YesToAll automatically approves Temp, cache,
    component-store, or volume operations. Interactive Y remains the acknowledgement.

.PARAMETER AcknowledgeDeleteAllTempAges
    Required with MinimumAgeDays 0 even in interactive Apply. This does not bypass
    file locks, reparse-point checks, trusted-root checks, or folder preservation.

.PARAMETER AllowManagedDevice
    Override the fail-closed block for detected AD/Entra/Workplace join, MDM,
    Configuration Manager, or incomplete management detection. Use only after formal
    IT/change-control approval; policy can still supersede local settings.

.PARAMETER AllowComputerRename
    Permit Restore when the stable device identity matches but the Windows computer
    name changed since Apply. Without this explicit restore-only override, a name
    mismatch is rejected to reduce cloned-image and wrong-endpoint risk.

.PARAMETER AllowNetworkChangeInRemoteSession
    Permit TCP/RSS Apply or Restore from a detected remote session. This does not
    remove the separate -AcknowledgeNetworkInterruption requirement.

.PARAMETER AcknowledgeNetworkInterruption
    Acknowledge possible connectivity impact. Required for every RSS mutation and for
    every TCP mutation/restore. It does not guarantee a remote session survives.

.PARAMETER AcknowledgeStorageIo
    Required before Optimize-Volume because it can create sustained storage I/O.

.PARAMETER AcknowledgeBatteryPowerPlan
    Required to Apply or Restore the Windows 10 High performance plan on a device
    with a battery. Unlike the Windows 11 AC-only vote, an active Windows 10 plan
    also governs its configured battery/DC values. The device must be on AC power.

.PARAMETER AcknowledgeServicedServiceIdentityDrift
    Permit Restore when an allowlisted service still has the same independently
    verified Microsoft executable/DLL paths, account SID, and service type, but its
    signed file hashes or signing certificate evidence changed after Apply (for
    example, through Windows servicing). It never permits an untrusted component
    or changed service mapping.

.PARAMETER ForceRestoreDivergedState
    Allow Restore to overwrite a current state that no longer matches the verified
    post-Apply or interrupted-restore state. The exact current state must first pass
    validation and is journaled for automatic rollback. Use only after inspection.

.PARAMETER IncludeStartupCommandLines
    Include startup command lines in an Audit report. Requires
    -IncludeSensitiveAuditData because arguments can contain secrets.

.PARAMETER IncludeSensitiveAuditData
    Include computer/domain identity, current-user SID, device identity hash, startup
    location/user, and stable adapter identity in the protected Audit report. The
    default redacts these fields and scopes collectors to selected operations.

.PARAMETER NonInteractive
    Assert that no prompt is permitted. Requires Recommended/YesToAll/NoToAll for
    Apply and YesToAll/NoToAll for Restore. Conflicting -Confirm or a prompt-causing
    ConfirmPreference is rejected.

.PARAMETER RequireReliableLogging
    Fail before mutation if a required log write cannot be persisted. Streaming output
    failures never abort DISM/Optimize-Volume mid-pipeline; they are reported after the
    external operation finishes, and the operation is marked failed for audit purposes.

.PARAMETER StopOnError
    Stop selecting further operations after the first operation/restore failure.
    Each reversible mutation is independently write-ahead journaled and verified;
    this switch does not make the whole session one transaction.

.PARAMETER ListOptimizations
    List IDs, categories, risks, reversibility, bulk eligibility, exact service names,
    and current availability. No Windows configuration is changed.

.PARAMETER NoColor
    Disable colored console output.

.PARAMETER PassThru
    Emit the catalog, audit snapshot, or result objects in addition to console output.

.PARAMETER WhatIf
    Show ShouldProcess actions without changing Windows. Apply WhatIf writes a
    protected diagnostic log but creates no rollback key or manifest.

.PARAMETER Confirm
    Request PowerShell ShouldProcess confirmation in addition to WinOptimize's Y/N/A
    consent. Use -Confirm:$false for approved noninteractive runs.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Audit

    Run a full, read-only audit with sensitive identity fields redacted.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -ListOptimizations

    List exact operation IDs and availability before selecting changes.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -CleanUserTemp -CleanWindowsTemp

    Prompt once for each distinct trusted Temp folder; preserve all folders.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -DisableOptionalServices

    Prompt individually for each present bulk-eligible optional service.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -ServiceName Fax,XblAuthManager

    Evaluate only two exact allowlisted services.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -Category Network -WhatIf

    Preview selected networking actions without a Windows mutation or rollback file.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -EnableReceiveSideScaling -AdapterInterfaceGuid '01234567-89ab-cdef-0123-456789abcdef' -AcknowledgeNetworkInterruption

    Prompt before enabling RSS on one exact eligible wired adapter.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Apply -AllRecommended -ConsentPolicy Recommended -NonInteractive -AcknowledgeIrreversibleActions -Confirm:$false

    Run only recommended Apply actions without prompts, with explicit deletion consent.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Restore -BackupPath "C:\ProgramData\WinOptimize\Backups\WinOptimize-backup-20260907-120000-000.json"

    Validate the manifest and its protected key, then prompt for each pending restore.

.EXAMPLE
    .\Invoke-WindowsOptimization.ps1 -Mode Restore -BackupPath "C:\ProgramData\WinOptimize\Backups\WinOptimize-backup-20260907-120000-000.json" -ConsentPolicy YesToAll -NonInteractive -Confirm:$false

    Restore all pending authenticated reversible records without interactive prompts.

.NOTES
    Version: 1.0.0
    Supported: 64-bit Windows PowerShell 5.1 Desktop on Windows 10/11 client for
    Apply/Restore. Run from a clean -NoProfile process. Windows 10 standard support
    ended 2025-10-14; verify LTSC/ESU coverage.

    Exit codes: 0 success/no requested change; 1 operation or restore failure/diverged
    state; 2 fatal preflight/infrastructure failure; 3 completed with unavailable,
    blocked, partial, or incomplete-audit results. Restart requirements are reported
    in results/logs; this script never forces a reboot.

    This script never disables Defender, Firewall, Windows Update, BITS, Event Log,
    SysMain, the page file, or other security/servicing foundations.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [ValidateSet('Audit', 'Apply', 'Restore')]
    [string]$Mode = 'Audit',

    [ValidateSet('Cleanup', 'Storage', 'Network', 'Power', 'Services', 'UserExperience', 'Startup')]
    [string[]]$Category,

    [string[]]$IncludeOptimization,
    [string[]]$ExcludeOptimization,
    [string[]]$RestoreOptimization,
    [string[]]$ServiceName,
    [guid[]]$AdapterInterfaceGuid,
    [ValidatePattern('^[A-Za-z]:?$')]
    [string[]]$VolumeDriveLetter,

    [ValidateSet('Ask', 'Recommended', 'YesToAll', 'NoToAll')]
    [string]$ConsentPolicy = 'Ask',

    [ValidateRange(0, 3650)]
    [int]$MinimumAgeDays = 7,

    [string]$BackupPath,
    [string]$LogDirectory,
    [string]$ReportPath,

    [switch]$AllRecommended,
    [switch]$CleanUserTemp,
    [switch]$CleanWindowsTemp,
    [switch]$ClearDeliveryOptimizationCache,
    [switch]$RunComponentCleanup,
    [switch]$OptimizeFixedVolumes,
    [switch]$NormalizeTcpAutoTuning,
    [switch]$EnableReceiveSideScaling,
    [switch]$SetBestPerformancePowerMode,
    [switch]$DisableClientAnimations,
    [switch]$ReviewStartupApps,
    [switch]$ReviewStorageSense,
    [switch]$DisableOptionalServices,
    [switch]$DisableDemandStartServices,

    [switch]$SkipRestorePoint,
    [switch]$AcknowledgeIrreversibleActions,
    [switch]$AcknowledgeDeleteAllTempAges,
    [switch]$AllowManagedDevice,
    [switch]$AllowComputerRename,
    [switch]$AllowNetworkChangeInRemoteSession,
    [switch]$AcknowledgeNetworkInterruption,
    [switch]$AcknowledgeStorageIo,
    [switch]$AcknowledgeBatteryPowerPlan,
    [switch]$AcknowledgeServicedServiceIdentityDrift,
    [switch]$ForceRestoreDivergedState,
    [switch]$IncludeStartupCommandLines,
    [switch]$IncludeSensitiveAuditData,
    [switch]$NonInteractive,
    [switch]$RequireReliableLogging,
    [switch]$StopOnError,
    [switch]$ListOptimizations,
    [switch]$NoColor,
    [switch]$PassThru
)

Microsoft.PowerShell.Core\Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ScriptName = 'WinOptimize'
$script:ScriptVersion = '1.0.0'
$script:SourcePath = [string]$PSCommandPath
$script:SchemaVersion = 1
$script:ManifestEnvelopeVersion = 1
$script:CmdletContext = $PSCmdlet
$script:ScriptBoundParameters = @{} + $PSBoundParameters
$script:LogPath = $null
$script:LogDirectory = $null
$script:BackupPath = $null
$script:ReportPath = $null
$script:Session = $null
$script:Results = Microsoft.PowerShell.Utility\New-Object System.Collections.ArrayList
$script:ConsentAllByGroup = @{}
$script:ExitCode = 0
$script:Mutex = $null
$script:IsWhatIf = [bool]$WhatIfPreference
$script:RestorePointAttempted = $false
$script:TrustedModuleAvailability = @{}
$script:TrustedModuleErrors = @{}
$script:OriginalPSModulePath = [string]$env:PSModulePath
$script:LastRssCandidateDiagnostics = $null
$script:NativeMethods = $null
$script:DeferredLogFailure = $null
$script:OperationFailureEscalated = $false
$script:CriticalServiceDenylist = @(
    'AppIDSvc', 'Appinfo', 'AppReadiness', 'BDESVC', 'BFE', 'BITS',
    'BrokerInfrastructure', 'CoreMessagingRegistrar', 'CryptSvc', 'DcomLaunch',
    'defragsvc', 'DeviceInstall', 'Dhcp', 'Dnscache', 'DPS', 'DsmSvc',
    'EapHost', 'EventLog', 'FontCache', 'gpsvc', 'KeyIso', 'LanmanServer',
    'LanmanWorkstation', 'LSM', 'mpssvc', 'msiserver', 'nsi', 'PlugPlay',
    'Power', 'ProfSvc', 'RemoteRegistry', 'RpcEptMapper', 'RpcSs', 'SamSs',
    'Schedule', 'SecurityHealthService', 'Sense', 'SgrmBroker', 'sppsvc',
    'StateRepository', 'SysMain', 'SystemEventsBroker', 'TermService',
    'TimeBrokerSvc', 'TrustedInstaller', 'UsoSvc', 'VaultSvc', 'W32Time',
    'WaaSMedicSvc', 'WdNisSvc', 'WdiSystemHost', 'Wecsvc', 'WerSvc',
    'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt', 'WinRM', 'WpnService',
    'wscsvc', 'wuauserv'
)

function Test-IsAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsRemoteSession {
    [CmdletBinding()]
    param()

    if ($null -ne (Get-Variable -Name PSSenderInfo -Scope Global -ErrorAction SilentlyContinue)) {
        return $true
    }
    if ([string]$Host.Name -eq 'ServerRemoteHost') {
        return $true
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$env:SSH_CONNECTION) -or
        -not [string]::IsNullOrWhiteSpace([string]$env:SSH_CLIENT) -or
        -not [string]::IsNullOrWhiteSpace([string]$env:SSH_TTY)) {
        return $true
    }
    if ([string]::IsNullOrWhiteSpace([string]$env:SESSIONNAME)) {
        return $true
    }

    return ($env:SESSIONNAME -notmatch '^Console$')
}

function Test-IsInteractiveUserContext {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$UserSid)

    if (@('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $UserSid) {
        return $false
    }
    if (-not [Environment]::UserInteractive) {
        return $false
    }
    try {
        $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        if ($sessionId -le 0) {
            return $false
        }
        Initialize-NativeMethods
        $sessionUserSid = [string]$script:NativeMethods.GetSessionUserSid($sessionId)
        return [string]::Equals($UserSid, $sessionUserSid, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Get-SafeFullPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([string]::IsNullOrWhiteSpace($expanded)) {
        throw 'A required path resolved to an empty value.'
    }

    $fullPath = [IO.Path]::GetFullPath($expanded)
    $pathRoot = [IO.Path]::GetPathRoot($fullPath)
    if ($fullPath -ieq $pathRoot) {
        return $fullPath
    }
    return $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Test-TrustedMicrosoftPowerShellAssembly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [type]$ImplementingType,
        [Parameter(Mandatory = $true)] [string]$TrustedPowerShellHome
    )

    $assembly = $ImplementingType.Assembly
    $assemblyName = $assembly.GetName()
    $allowedAssemblyNames = @(
        'Microsoft.PowerShell.Commands.Management',
        'Microsoft.PowerShell.Security',
        'Microsoft.PowerShell.Commands.Utility',
        'System.Management.Automation'
    )
    [byte[]]$tokenBytes = $assemblyName.GetPublicKeyToken()
    $token = if ($null -ne $tokenBytes) { ([BitConverter]::ToString($tokenBytes)).Replace('-', '').ToLowerInvariant() } else { '' }
    if ($allowedAssemblyNames -cnotcontains $assemblyName.Name -or $token -cne '31bf3856ad364e35') {
        return $false
    }

    $location = Get-SafeFullPath -Path ([string]$assembly.Location)
    if (Test-PathIsWithin -Path $location -Root $TrustedPowerShellHome) {
        return $true
    }
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory)) { return $false }
    foreach ($gacRoot in @(
        [IO.Path]::Combine($windowsDirectory, 'Microsoft.NET', 'assembly'),
        [IO.Path]::Combine($windowsDirectory, 'assembly')
    )) {
        if ([IO.Directory]::Exists($gacRoot) -and (Test-PathIsWithin -Path $location -Root $gacRoot)) {
            return $true
        }
    }
    return $false
}

function Initialize-TrustedCommandEnvironment {
    [CmdletBinding()]
    param()

    # PowerShell resolves aliases before functions. A profile alias whose name
    # matches any private function in this script could otherwise redirect an
    # elevated internal call before the normal command checks run. Parse this
    # exact script and fail closed on every visible alias collision before the
    # first private function is invoked. The bootstrap itself is invoked through
    # Function: at the bottom of the script so its own name cannot be aliased.
    $bootstrapTokens = $null
    $bootstrapParseErrors = $null
    if ([string]::IsNullOrWhiteSpace($script:SourcePath) -or -not [IO.File]::Exists($script:SourcePath)) {
        throw 'WinOptimize must run from one ordinary script file so its command surface can be verified.'
    }
    $bootstrapAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:SourcePath,
        [ref]$bootstrapTokens,
        [ref]$bootstrapParseErrors)
    if ($null -eq $bootstrapAst -or @($bootstrapParseErrors).Count -ne 0) {
        throw 'The running script could not be parsed exactly; trusted-command initialization was refused.'
    }
    $scriptFunctionDefinitions = @($bootstrapAst.FindAll({
        param($node)
        return ($node -is [System.Management.Automation.Language.FunctionDefinitionAst])
    }, $true))
    $visibleAliases = @(Microsoft.PowerShell.Utility\Get-Alias -ErrorAction Stop)
    foreach ($visibleAlias in $visibleAliases) {
        foreach ($functionDefinition in $scriptFunctionDefinitions) {
            if ([string]::Equals(
                    [string]$visibleAlias.Name,
                    [string]$functionDefinition.Name,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw ("Alias '{0}' conflicts with a private WinOptimize function. Start a clean 64-bit Windows PowerShell process with -NoProfile." -f $visibleAlias.Name)
            }
        }
    }

    $trustedPowerShellHome = Get-SafeFullPath -Path $PSHOME
    $trustedModuleRoot = Get-SafeFullPath -Path ([IO.Path]::Combine($trustedPowerShellHome, 'Modules'))
    if (-not [IO.Directory]::Exists($trustedModuleRoot)) {
        throw 'The inbox Windows PowerShell module directory is unavailable.'
    }

    # Profiles can shadow cmdlet names with functions or aliases. Abort before
    # using the unqualified utility/management commands used throughout the tool.
    $expectedCoreCommands = @(
        [pscustomobject]@{ Name = 'Add-Content'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Add-Member'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Add-Type'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ConvertFrom-Json'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ConvertTo-Json'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Format-Table'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'ForEach-Object'; Owner = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Get-ChildItem'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-Content'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-Date'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Get-Item'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-Module'; Owner = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Get-Service'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Get-Variable'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Import-Module'; Owner = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Join-Path'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Move-Item'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'New-Item'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'New-Object'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Out-Null'; Owner = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Out-String'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Read-Host'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Remove-Item'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Select-Object'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Sort-Object'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Split-Path'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Start-Process'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Start-Sleep'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Test-Path'; Owner = 'Microsoft.PowerShell.Management' },
        [pscustomobject]@{ Name = 'Where-Object'; Owner = 'Microsoft.PowerShell.Core' },
        [pscustomobject]@{ Name = 'Write-Error'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Write-Host'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Write-Output'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Write-Progress'; Owner = 'Microsoft.PowerShell.Utility' },
        [pscustomobject]@{ Name = 'Write-Warning'; Owner = 'Microsoft.PowerShell.Utility' }
    )
    foreach ($expectedCoreCommand in $expectedCoreCommands) {
        $resolvedCoreCommand = Microsoft.PowerShell.Core\Get-Command -Name $expectedCoreCommand.Name -ErrorAction Stop
        if ([string]$resolvedCoreCommand.CommandType -ne 'Cmdlet') {
            throw ("Command name '{0}' is shadowed by a profile or module. Start a clean 64-bit Windows PowerShell process with -NoProfile." -f $expectedCoreCommand.Name)
        }
        $actualOwner = if (-not [string]::IsNullOrWhiteSpace([string]$resolvedCoreCommand.ModuleName)) {
            [string]$resolvedCoreCommand.ModuleName
        }
        elseif ($null -ne $resolvedCoreCommand.PSSnapIn) {
            [string]$resolvedCoreCommand.PSSnapIn.Name
        }
        else { '' }
        if ($actualOwner -cne [string]$expectedCoreCommand.Owner -or
            -not (Test-TrustedMicrosoftPowerShellAssembly -ImplementingType $resolvedCoreCommand.ImplementingType -TrustedPowerShellHome $trustedPowerShellHome)) {
            throw ("Command '{0}' did not resolve from its trusted Microsoft Windows PowerShell owner." -f $expectedCoreCommand.Name)
        }
    }

    # Prevent elevated auto-loading from a per-user PSModulePath entry.  All
    # modules used by this tool are Windows inbox modules beneath $PSHOME.
    $env:PSModulePath = $trustedModuleRoot

    $moduleSpecifications = @(
        [pscustomobject]@{ Name = 'CimCmdlets'; Required = $true; Commands = @('Get-CimInstance') },
        [pscustomobject]@{ Name = 'Microsoft.PowerShell.Security'; Required = $true; Commands = @('Get-AuthenticodeSignature') },
        [pscustomobject]@{ Name = 'Storage'; Required = $false; Commands = @('Get-Volume', 'Optimize-Volume') },
        [pscustomobject]@{ Name = 'NetTCPIP'; Required = $false; Commands = @('Get-NetTCPSetting', 'Set-NetTCPSetting', 'Get-NetRoute') },
        [pscustomobject]@{ Name = 'NetAdapter'; Required = $false; Commands = @('Get-NetAdapter', 'Get-NetAdapterRss', 'Enable-NetAdapterRss', 'Disable-NetAdapterRss') },
        [pscustomobject]@{ Name = 'DeliveryOptimization'; Required = $false; Commands = @('Delete-DeliveryOptimizationCache') }
    )

    foreach ($specification in $moduleSpecifications) {
        foreach ($existingModule in @(Microsoft.PowerShell.Core\Get-Module -Name $specification.Name)) {
            if ([string]::IsNullOrWhiteSpace([string]$existingModule.ModuleBase) -or
                -not (Test-PathIsWithin -Path ([string]$existingModule.ModuleBase) -Root $trustedPowerShellHome -AllowEqual)) {
                throw ("An untrusted already-loaded module conflicts with inbox module '{0}'. Start a clean 64-bit Windows PowerShell process with -NoProfile." -f $specification.Name)
            }
        }

        $manifestPath = [IO.Path]::Combine($trustedModuleRoot, [string]$specification.Name, ("{0}.psd1" -f $specification.Name))
        if (-not [IO.File]::Exists($manifestPath)) {
            $script:TrustedModuleAvailability[$specification.Name] = $false
            $script:TrustedModuleErrors[$specification.Name] = 'Inbox module manifest not found.'
            if ($specification.Required) {
                throw ("Required inbox module '{0}' is unavailable." -f $specification.Name)
            }
            continue
        }

        try {
            $importedModules = @(Microsoft.PowerShell.Core\Import-Module -Name $manifestPath -Force -PassThru -Global -ErrorAction Stop)
            if ($importedModules.Count -lt 1 -or @($importedModules | Where-Object {
                [string]::IsNullOrWhiteSpace([string]$_.ModuleBase) -or
                -not (Test-PathIsWithin -Path ([string]$_.ModuleBase) -Root $trustedPowerShellHome -AllowEqual)
            }).Count -gt 0) {
                throw 'The imported module did not resolve beneath the trusted Windows PowerShell home.'
            }

            foreach ($commandName in $specification.Commands) {
                $qualifiedName = '{0}\{1}' -f $specification.Name, $commandName
                $resolvedCommands = @(Microsoft.PowerShell.Core\Get-Command -Name $qualifiedName -All -ErrorAction Stop)
                if ($resolvedCommands.Count -lt 1 -or @($resolvedCommands | Where-Object {
                    $null -eq $_.Module -or [string]::IsNullOrWhiteSpace([string]$_.Module.ModuleBase) -or
                    -not (Test-PathIsWithin -Path ([string]$_.Module.ModuleBase) -Root $trustedPowerShellHome -AllowEqual)
                }).Count -gt 0) {
                    throw ("Command '{0}' did not resolve exclusively from the trusted inbox module." -f $qualifiedName)
                }
            }
            $script:TrustedModuleAvailability[$specification.Name] = $true
        }
        catch {
            $script:TrustedModuleAvailability[$specification.Name] = $false
            $script:TrustedModuleErrors[$specification.Name] = $_.Exception.Message
            if ($specification.Required) {
                throw
            }
        }
    }

    foreach ($coreCommandName in @(
        'Microsoft.PowerShell.Management\Get-Service',
        'Microsoft.PowerShell.Management\Get-ItemPropertyValue',
        'Microsoft.PowerShell.Management\Checkpoint-Computer',
        'Microsoft.PowerShell.Security\Get-AuthenticodeSignature',
        'Microsoft.PowerShell.Utility\ConvertTo-Json'
    )) {
        $coreCommand = Microsoft.PowerShell.Core\Get-Command -Name $coreCommandName -ErrorAction Stop
        if (-not (Test-TrustedMicrosoftPowerShellAssembly -ImplementingType $coreCommand.ImplementingType -TrustedPowerShellHome $trustedPowerShellHome)) {
            throw ("Core command '{0}' did not resolve from the trusted Windows PowerShell installation." -f $coreCommandName)
        }
    }
}

function Get-TrustedTempRoots {
    [CmdletBinding()]
    param()

    $roots = New-Object System.Collections.ArrayList
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)

    if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
        [void]$roots.Add([pscustomobject][ordered]@{
            Id   = 'cleanup.user-temp'
            Path = Get-SafeFullPath -Path (Join-Path $localAppData 'Temp')
        })
    }
    if (-not [string]::IsNullOrWhiteSpace($windowsDirectory)) {
        [void]$roots.Add([pscustomobject][ordered]@{
            Id   = 'cleanup.windows-temp'
            Path = Get-SafeFullPath -Path (Join-Path $windowsDirectory 'Temp')
        })
    }

    return @($roots)
}

function Test-PathIsWithin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Root,
        [switch]$AllowEqual
    )

    $fullPath = Get-SafeFullPath -Path $Path
    $fullRoot = Get-SafeFullPath -Path $Root
    if ($AllowEqual -and $fullPath -ieq $fullRoot) {
        return $true
    }
    return $fullPath.StartsWith($fullRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-OperationalPathOutsideTempRoots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Purpose
    )

    foreach ($root in @(Get-TrustedTempRoots)) {
        if (Test-PathIsWithin -Path $Path -Root $root.Path -AllowEqual) {
            throw ("{0} path '{1}' cannot be inside a cleanup target." -f $Purpose, $Path)
        }
    }
}

function Test-IsUnsafeCleanupRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fullPath = Get-SafeFullPath -Path $Path
    if ($fullPath -notmatch '^[A-Za-z]:\\') {
        return $true
    }
    $trusted = @(Get-TrustedTempRoots | Where-Object { $_.Path -ieq $fullPath })
    return ($trusted.Count -lt 1)
}

function Test-PathContainsReparsePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $true
        }
        # FileInfo exposes its parent through Directory; DirectoryInfo exposes Parent.
        # Using Parent unconditionally throws under StrictMode for ordinary files.
        if ($current -is [IO.FileInfo]) {
            $current = $current.Directory
        }
        else {
            $current = $current.Parent
        }
    }
    return $false
}

function New-SafeDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force -Confirm:$false -WhatIf:$false -ErrorAction Stop | Out-Null
    }
}

function New-RestrictedDirectorySecurity {
    [CmdletBinding()]
    param(
        [switch]$IncludeCurrentUser
    )

    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                   [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $identities = New-Object System.Collections.ArrayList
    [void]$identities.Add($systemSid)
    [void]$identities.Add($administratorsSid)
    if ($IncludeCurrentUser) {
        [void]$identities.Add([Security.Principal.WindowsIdentity]::GetCurrent().User)
    }

    $expectedOwner = if ($IncludeCurrentUser) { [Security.Principal.WindowsIdentity]::GetCurrent().User } else { $administratorsSid }
    $security.SetOwner($expectedOwner)

    foreach ($identity in $identities) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow)
        [void]$security.AddAccessRule($rule)
    }
    return $security
}

function Set-RestrictedDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$IncludeCurrentUser
    )

    $security = New-RestrictedDirectorySecurity -IncludeCurrentUser:$IncludeCurrentUser
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $expectedOwner = if ($IncludeCurrentUser) { [Security.Principal.WindowsIdentity]::GetCurrent().User } else { $administratorsSid }
    [IO.Directory]::SetAccessControl($Path, $security)

    $verified = [IO.Directory]::GetAccessControl($Path, [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    $owner = $verified.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $expectedOwner.Value -or -not $verified.AreAccessRulesProtected) {
        throw ("Failed to establish a protected owner/DACL on '{0}'." -f $Path)
    }
}

function Set-RestrictedFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$IncludeCurrentUser
    )

    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetAccessRuleProtection($true, $false)
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $identities = @($systemSid, $administratorsSid)
    if ($IncludeCurrentUser) {
        $identities += [Security.Principal.WindowsIdentity]::GetCurrent().User
    }
    $expectedOwner = if ($IncludeCurrentUser) { [Security.Principal.WindowsIdentity]::GetCurrent().User } else { $administratorsSid }
    $security.SetOwner($expectedOwner)
    foreach ($identity in $identities) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $allow)
        [void]$security.AddAccessRule($rule)
    }
    [IO.File]::SetAccessControl($Path, $security)

    $verified = [IO.File]::GetAccessControl($Path, [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    $owner = $verified.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $expectedOwner.Value -or -not $verified.AreAccessRulesProtected) {
        throw ("Failed to establish a protected owner/DACL on '{0}'." -f $Path)
    }
}

function Assert-ExistingRestrictedFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$IncludeCurrentUser
    )

    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $expectedOwner = if ($IncludeCurrentUser) { [Security.Principal.WindowsIdentity]::GetCurrent().User } else { $administratorsSid }
    $allowedSidValues = @($administratorsSid.Value, $systemSid.Value)
    if ($IncludeCurrentUser) {
        $allowedSidValues += [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }

    $security = [IO.File]::GetAccessControl(
        $Path,
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $expectedOwner.Value -or -not $security.AreAccessRulesProtected) {
        throw ("Existing protected file '{0}' has an unexpected owner or inherited DACL." -f $Path)
    }

    $effectiveRights = @{}
    foreach ($rule in @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sidValue = $rule.IdentityReference.Value
        if ($allowedSidValues -notcontains $sidValue -or $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw ("Existing protected file '{0}' grants access outside the approved principals." -f $Path)
        }
        if (-not $effectiveRights.ContainsKey($sidValue)) {
            $effectiveRights[$sidValue] = [Security.AccessControl.FileSystemRights]0
        }
        $effectiveRights[$sidValue] = $effectiveRights[$sidValue] -bor $rule.FileSystemRights
    }
    foreach ($sidValue in $allowedSidValues) {
        if (-not $effectiveRights.ContainsKey($sidValue) -or
            ($effectiveRights[$sidValue] -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw ("Existing protected file '{0}' is missing an expected full-control principal." -f $Path)
        }
    }
}

function Write-NewRestrictedTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Text,
        [switch]$IncludeCurrentUser
    )

    [byte[]]$bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    Set-RestrictedFileAcl -Path $Path -IncludeCurrentUser:$IncludeCurrentUser
}

function Assert-ExistingRestrictedDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$IncludeCurrentUser
    )

    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $expectedOwner = if ($IncludeCurrentUser) { [Security.Principal.WindowsIdentity]::GetCurrent().User } else { $administratorsSid }
    $allowedSidValues = @($administratorsSid.Value, $systemSid.Value)
    if ($IncludeCurrentUser) {
        $allowedSidValues += [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }

    $security = [IO.Directory]::GetAccessControl(
        $Path,
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access)
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $expectedOwner.Value -or -not $security.AreAccessRulesProtected) {
        throw ("Existing protected data root '{0}' has an unexpected owner or inherited DACL." -f $Path)
    }

    $effectiveRights = @{}
    foreach ($rule in @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        $sidValue = $rule.IdentityReference.Value
        if ($allowedSidValues -notcontains $sidValue -or $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw ("Existing protected data root '{0}' grants access outside the approved principals." -f $Path)
        }
        if (-not $effectiveRights.ContainsKey($sidValue)) {
            $effectiveRights[$sidValue] = [Security.AccessControl.FileSystemRights]0
        }
        $effectiveRights[$sidValue] = $effectiveRights[$sidValue] -bor $rule.FileSystemRights
    }
    foreach ($sidValue in $allowedSidValues) {
        if (-not $effectiveRights.ContainsKey($sidValue) -or
            ($effectiveRights[$sidValue] -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw ("Existing protected data root '{0}' is missing an expected full-control principal." -f $Path)
        }
    }
}

function Initialize-SecureDataRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$IncludeCurrentUser
    )

    if ($Path -notmatch '^[A-Za-z]:\\') {
        throw 'WinOptimize data must be stored on a local drive-letter path.'
    }
    Initialize-NativeMethods
    $desiredSecurity = New-RestrictedDirectorySecurity -IncludeCurrentUser:$IncludeCurrentUser
    [byte[]]$securityDescriptor = $desiredSecurity.GetSecurityDescriptorBinaryForm()
    $createdSecurely = $script:NativeMethods.CreateDirectorySecure($Path, $securityDescriptor)
    $existed = -not $createdSecurely
    if ($existed -and -not [IO.Directory]::Exists($Path)) {
        throw ("WinOptimize data path '{0}' already exists but is not a directory." -f $Path)
    }

    $guardChain = @()
    try {
        $guardChain = @(Open-DirectoryGuardChain -Path $Path)
        if (Test-PathContainsReparsePoint -Path $Path) {
            throw ("WinOptimize data path '{0}' or a parent is a reparse point." -f $Path)
        }
        if ((Get-DriveTypeForPath -Path $Path) -ne [IO.DriveType]::Fixed) {
            throw 'WinOptimize data must be stored on a local fixed drive.'
        }
        if ($existed) {
            Assert-ExistingRestrictedDirectoryAcl -Path $Path -IncludeCurrentUser:$IncludeCurrentUser
        }
        Set-RestrictedDirectoryAcl -Path $Path -IncludeCurrentUser:$IncludeCurrentUser
        return $Path
    }
    finally {
        foreach ($guard in @($guardChain)) {
            if ($null -ne $guard) { $guard.Dispose() }
        }
    }
}

function Get-DefaultDataRoot {
    [CmdletBinding()]
    param()

    $isAdmin = $false
    try {
        $isAdmin = Test-IsAdministrator
    }
    catch {
        $isAdmin = $false
    }

    if ($isAdmin) {
        $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        if ([string]::IsNullOrWhiteSpace($commonData)) {
            throw 'The Windows CommonApplicationData known folder could not be resolved.'
        }
        return (Initialize-SecureDataRoot -Path (Join-Path $commonData $script:ScriptName))
    }

    $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localData)) {
        throw 'The Windows LocalApplicationData known folder could not be resolved.'
    }
    return (Initialize-SecureDataRoot -Path (Join-Path $localData $script:ScriptName) -IncludeCurrentUser)
}

function Assert-PathWithinDataRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$DataRoot,
        [Parameter(Mandatory = $true)] [string]$Purpose,
        [switch]$AllowEqual
    )

    if (-not (Test-PathIsWithin -Path $Path -Root $DataRoot -AllowEqual:$AllowEqual)) {
        throw ("Custom {0} path must remain inside the protected data root '{1}'." -f $Purpose, $DataRoot)
    }
}

function Assert-SafeOperationalFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Purpose
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded -notmatch '^[A-Za-z]:\\' -or
        $expanded.Substring(2).Contains(':') -or $expanded -match '[\x00-\x1f<>"/|\*\?]') {
        throw ("{0} must be one ordinary local drive-letter file path without streams, wildcards, device syntax, or control characters." -f $Purpose)
    }

    $relative = $expanded.Substring(3)
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative.EndsWith('\', [StringComparison]::Ordinal)) {
        throw ("{0} must include a nonempty file name." -f $Purpose)
    }
    $components = $relative.Split([char]'\')
    foreach ($component in $components) {
        if ([string]::IsNullOrWhiteSpace($component) -or $component -eq '.' -or $component -eq '..' -or
            $component.EndsWith('.', [StringComparison]::Ordinal) -or
            $component.EndsWith(' ', [StringComparison]::Ordinal) -or
            $component -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
            throw ("{0} contains an empty, relative, reserved, or trailing-dot/space path component." -f $Purpose)
        }
    }

    $fullPath = Get-SafeFullPath -Path $expanded
    if ($fullPath -ine $expanded) {
        throw ("{0} changed during canonicalization and was refused to prevent path aliasing." -f $Purpose)
    }
    return $fullPath
}

function Get-TrustedSystemExecutable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('sc.exe', 'powercfg.exe', 'Dism.exe', 'dsregcmd.exe')]
        [string]$Name,
        [switch]$Optional
    )

    $systemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'The Windows system directory could not be resolved.'
    }
    $path = Join-Path $systemDirectory $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ($Optional) { return $null }
        throw ("Required Windows executable is unavailable: {0}" -f $path)
    }
    return $path
}

function Initialize-Logging {
    [CmdletBinding()]
    param()

    $dataRoot = Get-DefaultDataRoot
    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        $script:LogDirectory = Join-Path $dataRoot 'Logs'
    }
    else {
        $script:LogDirectory = Get-SafeFullPath -Path $LogDirectory
        Assert-PathWithinDataRoot -Path $script:LogDirectory -DataRoot $dataRoot -Purpose 'log directory' -AllowEqual
    }

    Assert-OperationalPathOutsideTempRoots -Path $script:LogDirectory -Purpose 'Log directory'
    New-SafeDirectory -Path $script:LogDirectory
    if (Test-PathContainsReparsePoint -Path $script:LogDirectory) {
        throw 'Log directory or one of its parents is a reparse point.'
    }
    Set-RestrictedDirectoryAcl -Path $script:LogDirectory -IncludeCurrentUser:(-not (Test-IsAdministrator))
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $unique = [guid]::NewGuid().ToString('N')
    $script:LogPath = Join-Path $script:LogDirectory ("WinOptimize-{0}-{1}-{2}.log" -f $Mode.ToLowerInvariant(), $stamp, $unique)
    $header = ("{0}`tINFO`t{1} {2} log started. Mode={3}; ProcessId={4}" -f ([DateTime]::UtcNow.ToString('o')), $script:ScriptName, $script:ScriptVersion, $Mode, $PID) + [Environment]::NewLine
    Write-NewRestrictedTextFile -Path $script:LogPath -Text $header -IncludeCurrentUser:(-not (Test-IsAdministrator))
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [switch]$NoConsole,

        [switch]$DeferFailure
    )

    $cleanMessage = ($Message -replace "[\r\n\t]+", ' ').Trim()
    $line = "{0}`t{1}`t{2}" -f ([DateTime]::UtcNow.ToString('o')), $Level, $cleanMessage

    if (-not [string]::IsNullOrWhiteSpace([string]$script:LogPath)) {
        try {
            Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -Confirm:$false -WhatIf:$false -ErrorAction Stop
        }
        catch {
            # Logging failure must not recursively call Write-Log.
            if ($DeferFailure) {
                if ($null -eq $script:DeferredLogFailure) {
                    $script:DeferredLogFailure = $_.Exception.Message
                    Write-Warning 'Streaming output could not be appended to the log; the external operation will be allowed to finish.'
                }
                return
            }
            if ($RequireReliableLogging) {
                throw 'The log file could not be updated and -RequireReliableLogging is active.'
            }
            Write-Warning 'The log file could not be updated.'
        }
    }

    if ($NoConsole) {
        return
    }

    if ($NoColor) {
        Write-Host ("[{0}] {1}" -f $Level, $cleanMessage)
        return
    }

    $color = switch ($Level) {
        'DEBUG'   { 'DarkGray' }
        'INFO'    { 'Cyan' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    Write-Host ("[{0}] {1}" -f $Level, $cleanMessage) -ForegroundColor $color
}

function Write-UiHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string]$Message,
        [ConsoleColor]$Color
    )

    if ($NoColor -or -not $PSBoundParameters.ContainsKey('Color')) {
        Microsoft.PowerShell.Utility\Write-Host $Message
    }
    else {
        Microsoft.PowerShell.Utility\Write-Host $Message -ForegroundColor $Color
    }
}

function Format-ErrorRecordForLog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $invocation = $ErrorRecord.InvocationInfo
    $location = if ($null -ne $invocation) {
        '{0}:{1}:{2}; command={3}' -f [string]$invocation.ScriptName,
            [int]$invocation.ScriptLineNumber, [int]$invocation.OffsetInLine,
            [string]$invocation.MyCommand.Name
    }
    else { 'unavailable' }
    $stack = if ([string]::IsNullOrWhiteSpace([string]$ErrorRecord.ScriptStackTrace)) { 'unavailable' } else { [string]$ErrorRecord.ScriptStackTrace }
    return 'message={0}; exception={1}; fqid={2}; category={3}; location={4}; scriptStack={5}' -f
        $ErrorRecord.Exception.Message, $ErrorRecord.Exception.GetType().FullName,
        $ErrorRecord.FullyQualifiedErrorId, [string]$ErrorRecord.CategoryInfo, $location, $stack
}

function Format-ByteSize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ("{0} bytes" -f $Bytes)
}

function Add-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [Parameter(Mandatory = $true)] [string]$Category,
        [Parameter(Mandatory = $true)] [string]$Status,
        [Parameter(Mandatory = $true)] [string]$Message,
        [bool]$RestartRequired = $false
    )

    $result = [pscustomobject][ordered]@{
        Id              = $Id
        Category        = $Category
        Status          = $Status
        Message         = $Message
        RestartRequired = $RestartRequired
        TimestampUtc    = [DateTime]::UtcNow.ToString('o')
    }
    [void]$script:Results.Add($result)
    return $result
}

function Set-PartialExitCode {
    [CmdletBinding()]
    param()

    if ($script:ExitCode -eq 0) {
        $script:ExitCode = 3
    }
}

function Enter-SingleInstance {
    [CmdletBinding()]
    param()

    $createdNew = $false
    $name = 'Global\WinOptimize-9C1D0F91-4A54-41EE-A10C-B08A6D4D77ED'
    try {
        $script:Mutex = New-Object Threading.Mutex($true, $name, [ref]$createdNew)
    }
    catch {
        if (@('Apply', 'Restore') -contains $Mode -and -not $ListOptimizations) {
            throw 'The machine-wide optimization lock could not be established; Apply/Restore was refused.'
        }
        $name = 'Local\WinOptimize-9C1D0F91-4A54-41EE-A10C-B08A6D4D77ED'
        $script:Mutex = New-Object Threading.Mutex($true, $name, [ref]$createdNew)
    }

    if (-not $createdNew) {
        throw 'Another WinOptimize instance is already running.'
    }
}

function Exit-SingleInstance {
    [CmdletBinding()]
    param()

    if ($null -ne $script:Mutex) {
        try { $script:Mutex.ReleaseMutex() } catch { }
        try { $script:Mutex.Dispose() } catch { }
        $script:Mutex = $null
    }
}

function Test-NativeHelperTypeContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [type]$Type,
        [Parameter(Mandatory = $true)] [string]$Namespace
    )

    $expected = @(
        [pscustomobject]@{ Name = 'GetClientAreaAnimation'; ReturnType = 'System.Boolean'; Parameters = @() },
        [pscustomobject]@{ Name = 'CreateDirectorySecure'; ReturnType = 'System.Boolean'; Parameters = @('System.String', 'System.Byte[]') },
        [pscustomobject]@{ Name = 'SetClientAreaAnimation'; ReturnType = 'System.Void'; Parameters = @('System.Boolean') },
        [pscustomobject]@{ Name = 'GetACPowerMode'; ReturnType = 'System.Guid'; Parameters = @() },
        [pscustomobject]@{ Name = 'SetACPowerMode'; ReturnType = 'System.Void'; Parameters = @('System.Guid') },
        [pscustomobject]@{ Name = 'GetPowerStatus'; ReturnType = "${Namespace}.PowerStatusSnapshot"; Parameters = @() },
        [pscustomobject]@{ Name = 'GetSessionUserSid'; ReturnType = 'System.String'; Parameters = @('System.Int32') },
        [pscustomobject]@{ Name = 'OpenDirectoryGuard'; ReturnType = "${Namespace}.DirectoryGuard"; Parameters = @('System.String') },
        [pscustomobject]@{ Name = 'DeleteOldRegularFile'; ReturnType = "${Namespace}.DeleteFileResult"; Parameters = @('System.String', 'System.String', 'System.Int64') }
    )
    $flags = [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::DeclaredOnly
    $methods = @($Type.GetMethods($flags))
    if ($methods.Count -ne $expected.Count) { return $false }

    foreach ($specification in $expected) {
        $matches = @($methods | Where-Object { $_.Name -ceq $specification.Name })
        if ($matches.Count -ne 1 -or $matches[0].ReturnType.FullName -cne $specification.ReturnType) {
            return $false
        }
        $actualParameterTypes = @($matches[0].GetParameters() | ForEach-Object { $_.ParameterType.FullName })
        if ($actualParameterTypes.Count -ne $specification.Parameters.Count) { return $false }
        for ($index = 0; $index -lt $actualParameterTypes.Count; $index++) {
            if ($actualParameterTypes[$index] -cne $specification.Parameters[$index]) { return $false }
        }
    }
    return $true
}

function Initialize-NativeMethods {
    [CmdletBinding()]
    param()

    if ($null -ne $script:NativeMethods) {
        return
    }

    # A fresh unpredictable namespace prevents a profile or an earlier runspace
    # from preloading a same-named type whose method bodies this elevated script
    # might otherwise trust. Add-Type itself is validated as an inbox cmdlet.
    $nativeNamespace = 'WinOptimize.Run_{0}' -f ([guid]::NewGuid().ToString('N'))

    $typeDefinition = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace __WINOPT_NAMESPACE__
{
    public sealed class NativeMethods
    {
        private const uint SPI_GETCLIENTAREAANIMATION = 0x1042;
        private const uint SPI_SETCLIENTAREAANIMATION = 0x1043;
        private const uint SPIF_UPDATEINIFILE = 0x0001;
        private const uint SPIF_SENDCHANGE = 0x0002;

        private const uint FILE_LIST_DIRECTORY = 0x0001;
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint DELETE = 0x00010000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const int ERROR_ALREADY_EXISTS = 183;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool SystemParametersInfoGet(
            uint uiAction,
            uint uiParam,
            ref int pvParam,
            uint fWinIni);

        [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool SystemParametersInfoSet(
            uint uiAction,
            uint uiParam,
            IntPtr pvParam,
            uint fWinIni);

        [DllImport("powrprof.dll", SetLastError = false)]
        private static extern UInt32 PowerGetUserConfiguredACPowerMode(out Guid powerModeGuid);

        [DllImport("powrprof.dll", SetLastError = false)]
        private static extern UInt32 PowerSetUserConfiguredACPowerMode(ref Guid powerModeGuid);

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_POWER_STATUS
        {
            public byte ACLineStatus;
            public byte BatteryFlag;
            public byte BatteryLifePercent;
            public byte SystemStatusFlag;
            public uint BatteryLifeTime;
            public uint BatteryFullLifeTime;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

        private enum WTS_INFO_CLASS
        {
            WTSUserName = 5,
            WTSDomainName = 7
        }

        [DllImport("Wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQuerySessionInformation(
            IntPtr server,
            int sessionId,
            WTS_INFO_CLASS infoClass,
            out IntPtr buffer,
            out int bytesReturned);

        [DllImport("Wtsapi32.dll", ExactSpelling = true)]
        private static extern void WTSFreeMemory(IntPtr memory);

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFO
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        private enum FILE_INFO_BY_HANDLE_CLASS
        {
            FileDispositionInfo = 4
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateDirectorySecureNative(
            string path,
            ref SECURITY_ATTRIBUTES securityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            FILE_INFO_BY_HANDLE_CLASS fileInformationClass,
            ref FILE_DISPOSITION_INFO fileInformation,
            uint bufferSize);

        public bool GetClientAreaAnimation()
        {
            int enabled = 0;
            if (!SystemParametersInfoGet(SPI_GETCLIENTAREAANIMATION, 0, ref enabled, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return enabled != 0;
        }

        public bool CreateDirectorySecure(string path, byte[] securityDescriptor)
        {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
            {
                throw new ArgumentException("A security descriptor is required.", "securityDescriptor");
            }

            IntPtr descriptor = Marshal.AllocHGlobal(securityDescriptor.Length);
            try
            {
                Marshal.Copy(securityDescriptor, 0, descriptor, securityDescriptor.Length);
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                    lpSecurityDescriptor = descriptor,
                    bInheritHandle = false
                };
                if (CreateDirectorySecureNative(path, ref attributes))
                {
                    return true;
                }

                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_ALREADY_EXISTS)
                {
                    return false;
                }
                throw new Win32Exception(error);
            }
            finally
            {
                Marshal.FreeHGlobal(descriptor);
            }
        }

        public void SetClientAreaAnimation(bool enabled)
        {
            IntPtr value = enabled ? new IntPtr(1) : IntPtr.Zero;
            if (!SystemParametersInfoSet(
                SPI_SETCLIENTAREAANIMATION,
                0,
                value,
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public Guid GetACPowerMode()
        {
            Guid value;
            UInt32 result = PowerGetUserConfiguredACPowerMode(out value);
            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }
            return value;
        }

        public void SetACPowerMode(Guid value)
        {
            UInt32 result = PowerSetUserConfiguredACPowerMode(ref value);
            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }
        }

        public PowerStatusSnapshot GetPowerStatus()
        {
            SYSTEM_POWER_STATUS status;
            if (!GetSystemPowerStatus(out status))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            bool batteryReliable = status.BatteryFlag != 255;
            bool hasBattery = batteryReliable && (status.BatteryFlag & 128) == 0;
            bool acReliable = status.ACLineStatus == 0 || status.ACLineStatus == 1;
            int batteryPercent = status.BatteryLifePercent <= 100 ? (int)status.BatteryLifePercent : -1;
            return new PowerStatusSnapshot(
                hasBattery,
                batteryReliable,
                (int)status.ACLineStatus,
                acReliable,
                batteryPercent);
        }

        public string GetSessionUserSid(int sessionId)
        {
            if (sessionId <= 0)
            {
                throw new ArgumentOutOfRangeException("sessionId");
            }

            string userName = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSUserName);
            string domainName = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSDomainName);
            if (String.IsNullOrWhiteSpace(userName))
            {
                throw new InvalidOperationException("The interactive session has no resolvable user name.");
            }

            NTAccount account = String.IsNullOrWhiteSpace(domainName)
                ? new NTAccount(userName)
                : new NTAccount(domainName, userName);
            SecurityIdentifier sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            return sid.Value;
        }

        public DirectoryGuard OpenDirectoryGuard(string path)
        {
            SafeFileHandle handle = CreateFile(
                path,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }

            try
            {
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw new InvalidOperationException("Directory is a reparse point.");
                }
                if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    throw new InvalidOperationException("Path is not a directory.");
                }

                ulong fileId = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
                return new DirectoryGuard(handle, GetFinalDosPath(handle), information.VolumeSerialNumber, fileId);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public DeleteFileResult DeleteOldRegularFile(string path, string approvedRoot, long cutoffFileTimeUtc)
        {
            using (SafeFileHandle handle = CreateFile(
                path,
                DELETE | FILE_READ_ATTRIBUTES,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    return new DeleteFileResult("ReparsePoint", 0);
                }
                if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    return new DeleteFileResult("NotRegularFile", 0);
                }

                string finalPath = NormalizeFinalPath(GetFinalDosPath(handle));
                string root = Path.GetFullPath(approvedRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!finalPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    throw new UnauthorizedAccessException("The opened file resolved outside the approved temporary root.");
                }

                long lastWriteFileTime = ((long)information.LastWriteTime.dwHighDateTime << 32) |
                                         (uint)information.LastWriteTime.dwLowDateTime;
                if (lastWriteFileTime > cutoffFileTimeUtc)
                {
                    return new DeleteFileResult("Recent", 0);
                }

                long length = ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
                FILE_DISPOSITION_INFO disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
                if (!SetFileInformationByHandle(
                    handle,
                    FILE_INFO_BY_HANDLE_CLASS.FileDispositionInfo,
                    ref disposition,
                    (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO))))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return new DeleteFileResult("Deleted", length);
            }
        }

        private static string GetFinalDosPath(SafeFileHandle handle)
        {
            uint capacity = 512;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                StringBuilder buffer = new StringBuilder((int)capacity);
                uint length = GetFinalPathNameByHandle(handle, buffer, capacity, 0);
                if (length == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (length < capacity)
                {
                    return buffer.ToString();
                }
                if (length >= 32768)
                {
                    throw new PathTooLongException("The resolved Windows path exceeds the supported maximum length.");
                }
                capacity = length + 1;
            }
            throw new IOException("The resolved Windows path length changed repeatedly while it was being validated.");
        }

        private static string QuerySessionString(int sessionId, WTS_INFO_CLASS infoClass)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytesReturned = 0;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytesReturned))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                if (buffer == IntPtr.Zero || bytesReturned <= 2)
                {
                    return String.Empty;
                }
                return Marshal.PtrToStringUni(buffer) ?? String.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    WTSFreeMemory(buffer);
                }
            }
        }

        private static string NormalizeFinalPath(string path)
        {
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFullPath(@"\\" + path.Substring(8));
            }
            if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFullPath(path.Substring(4));
            }
            return Path.GetFullPath(path);
        }
    }

    public sealed class DirectoryGuard : IDisposable
    {
        private SafeFileHandle handle;

        internal DirectoryGuard(SafeFileHandle handle, string finalPath, uint volumeSerialNumber, ulong fileId)
        {
            this.handle = handle;
            this.FinalPath = finalPath;
            this.VolumeSerialNumber = volumeSerialNumber;
            this.FileId = fileId;
        }

        public string FinalPath { get; private set; }
        public uint VolumeSerialNumber { get; private set; }
        public ulong FileId { get; private set; }

        public void Dispose()
        {
            if (this.handle != null)
            {
                this.handle.Dispose();
                this.handle = null;
            }
        }
    }

    public sealed class PowerStatusSnapshot
    {
        internal PowerStatusSnapshot(bool hasBattery, bool batteryDetectionReliable, int acLineStatus, bool acLineStatusReliable, int batteryLifePercent)
        {
            this.HasBattery = hasBattery;
            this.BatteryDetectionReliable = batteryDetectionReliable;
            this.AcLineStatus = acLineStatus;
            this.AcLineStatusReliable = acLineStatusReliable;
            this.BatteryLifePercent = batteryLifePercent;
        }

        public bool HasBattery { get; private set; }
        public bool BatteryDetectionReliable { get; private set; }
        public int AcLineStatus { get; private set; }
        public bool AcLineStatusReliable { get; private set; }
        public int BatteryLifePercent { get; private set; }
    }

    public sealed class DeleteFileResult
    {
        internal DeleteFileResult(string status, long length)
        {
            this.Status = status;
            this.Length = length;
        }

        public string Status { get; private set; }
        public long Length { get; private set; }
    }
}
'@

    $typeDefinition = $typeDefinition.Replace('__WINOPT_NAMESPACE__', $nativeNamespace)
    $loadedTypes = @(Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $typeDefinition -Language CSharp -PassThru -ErrorAction Stop)
    $loadedType = @($loadedTypes | Where-Object { $_.FullName -ceq ("{0}.NativeMethods" -f $nativeNamespace) })
    if ($loadedType.Count -ne 1) {
        throw 'The WinOptimize native helper did not load as expected.'
    }
    if (-not (Test-NativeHelperTypeContract -Type $loadedType[0] -Namespace $nativeNamespace)) {
        throw 'The WinOptimize native helper exposed an unexpected interface.'
    }
    $script:NativeMethods = [Activator]::CreateInstance($loadedType[0])
}

function Get-SystemPowerSafetyState {
    [CmdletBinding()]
    param()

    Initialize-NativeMethods
    $nativeState = $script:NativeMethods.GetPowerStatus()
    $acLineStatus = switch ([int]$nativeState.AcLineStatus) {
        0 { 'Offline' }
        1 { 'Online' }
        default { 'Unknown' }
    }
    return [pscustomobject][ordered]@{
        HasBattery              = [bool]$nativeState.HasBattery
        BatteryDetectionReliable = [bool]$nativeState.BatteryDetectionReliable
        AcLineStatus            = $acLineStatus
        AcLineStatusReliable    = [bool]$nativeState.AcLineStatusReliable
        BatteryLifePercent      = [int]$nativeState.BatteryLifePercent
    }
}

function Get-OperatingSystemInfo {
    [CmdletBinding()]
    param()

    $os = CimCmdlets\Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = CimCmdlets\Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $computerProduct = CimCmdlets\Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    $machineGuid = [string](Microsoft.PowerShell.Management\Get-ItemPropertyValue `
        -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography' `
        -Name 'MachineGuid' -ErrorAction Stop)
    $productUuid = [string]$computerProduct.UUID
    $parsedMachineGuid = [guid]::Empty
    $parsedProductUuid = [guid]::Empty
    $allFfGuid = [guid]'ffffffff-ffff-ffff-ffff-ffffffffffff'
    $machineGuidValid = [guid]::TryParse($machineGuid, [ref]$parsedMachineGuid) -and
        $parsedMachineGuid -ne [guid]::Empty -and $parsedMachineGuid -ne $allFfGuid
    $productUuidValid = [guid]::TryParse($productUuid, [ref]$parsedProductUuid) -and
        $parsedProductUuid -ne [guid]::Empty -and $parsedProductUuid -ne $allFfGuid
    $deviceIdentityReliable = $machineGuidValid -and $productUuidValid
    $identityMaterial = '{0}|{1}' -f $machineGuid, $productUuid
    $identityHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $identityBytes = $identityHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($identityMaterial))
        $deviceIdentityHash = ([BitConverter]::ToString($identityBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $identityHasher.Dispose()
    }
    $version = [version]$os.Version
    $family = if ($version.Build -ge 22000) { 'Windows 11' } elseif ($version.Major -eq 10) { 'Windows 10' } else { 'Unsupported' }
    $azureAdJoined = $false
    $enterpriseJoined = $false
    $workplaceJoined = $false
    $dsregDetectionSucceeded = $false
    $dsregPath = Get-TrustedSystemExecutable -Name 'dsregcmd.exe' -Optional
    if ($null -ne $dsregPath) {
        try {
            $dsregOutput = @(& $dsregPath /status 2>$null) -join [Environment]::NewLine
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($dsregOutput)) {
                $azureMatch = [regex]::Match($dsregOutput, '(?im)^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$')
                $enterpriseMatch = [regex]::Match($dsregOutput, '(?im)^\s*EnterpriseJoined\s*:\s*(YES|NO)\s*$')
                $workplaceMatch = [regex]::Match($dsregOutput, '(?im)^\s*WorkplaceJoined\s*:\s*(YES|NO)\s*$')
                if ($azureMatch.Success -and $enterpriseMatch.Success -and $workplaceMatch.Success) {
                    $dsregDetectionSucceeded = $true
                    $azureAdJoined = $azureMatch.Groups[1].Value -eq 'YES'
                    $enterpriseJoined = $enterpriseMatch.Groups[1].Value -eq 'YES'
                    $workplaceJoined = $workplaceMatch.Groups[1].Value -eq 'YES'
                }
            }
        }
        catch {
            $dsregDetectionSucceeded = $false
        }
    }

    $mdmEnrollmentDetected = $false
    $mdmDetectionSucceeded = $false
    try {
        $enrollmentRoot = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments'
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $enrollmentRoot) {
            foreach ($enrollmentKey in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $enrollmentRoot -ErrorAction Stop)) {
                $properties = Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $enrollmentKey.PSPath -ErrorAction Stop
                $providerProperty = if ($null -ne $properties) { $properties.PSObject.Properties['ProviderID'] } else { $null }
                $enrollmentTypeProperty = if ($null -ne $properties) { $properties.PSObject.Properties['EnrollmentType'] } else { $null }
                if ($null -ne $properties -and
                    (($null -ne $providerProperty -and -not [string]::IsNullOrWhiteSpace([string]$providerProperty.Value)) -or
                     $null -ne $enrollmentTypeProperty)) {
                    $mdmEnrollmentDetected = $true
                    break
                }
            }
        }
        $mdmDetectionSucceeded = $true
    }
    catch {
        $mdmDetectionSucceeded = $false
    }

    $configMgrDetected = $false
    $configMgrDetectionSucceeded = $false
    try {
        $configMgrService = CimCmdlets\Get-CimInstance -ClassName Win32_Service -Filter "Name='CcmExec'" -ErrorAction Stop
        $configMgrDetected = $null -ne $configMgrService
        $configMgrDetectionSucceeded = $true
    }
    catch {
        $configMgrDetectionSucceeded = $false
    }
    $managementSignals = New-Object System.Collections.ArrayList
    if ([bool]$computer.PartOfDomain) { [void]$managementSignals.Add('ActiveDirectoryDomain') }
    if ($azureAdJoined) { [void]$managementSignals.Add('MicrosoftEntraJoined') }
    if ($enterpriseJoined) { [void]$managementSignals.Add('EnterpriseJoined') }
    if ($workplaceJoined) { [void]$managementSignals.Add('WorkplaceRegistered') }
    if ($mdmEnrollmentDetected) { [void]$managementSignals.Add('MdmEnrollment') }
    if ($configMgrDetected) { [void]$managementSignals.Add('ConfigurationManagerClient') }
    $managementDetectionReliable = $dsregDetectionSucceeded -and $mdmDetectionSucceeded -and $configMgrDetectionSucceeded

    $lastBoot = [datetime]$os.LastBootUpTime
    try {
        $powerSafety = Get-SystemPowerSafetyState
    }
    catch {
        $powerSafety = [pscustomobject][ordered]@{
            HasBattery = $false
            BatteryDetectionReliable = $false
            AcLineStatus = 'Unknown'
            AcLineStatusReliable = $false
            BatteryLifePercent = -1
        }
    }

    return [pscustomobject][ordered]@{
        Caption           = [string]$os.Caption
        Version           = [string]$os.Version
        BuildNumber       = [int]$os.BuildNumber
        Family            = $family
        ProductType       = [int]$os.ProductType
        OSArchitecture    = [string]$os.OSArchitecture
        LastBootUpTimeUtc = $lastBoot.ToUniversalTime().ToString('o')
        ComputerName      = [Environment]::MachineName
        DeviceIdentityHash = $deviceIdentityHash
        DeviceIdentityReliable = [bool]$deviceIdentityReliable
        CurrentUserSid    = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Manufacturer      = [string]$computer.Manufacturer
        Model             = [string]$computer.Model
        PartOfDomain      = [bool]$computer.PartOfDomain
        AzureAdJoined     = [bool]$azureAdJoined
        EnterpriseJoined  = [bool]$enterpriseJoined
        WorkplaceJoined   = [bool]$workplaceJoined
        MdmEnrolled       = [bool]$mdmEnrollmentDetected
        ConfigMgrDetected = [bool]$configMgrDetected
        ConfigMgrDetectionSucceeded = [bool]$configMgrDetectionSucceeded
        ManagementSignals = @($managementSignals)
        ManagementDetectionReliable = [bool]$managementDetectionReliable
        IsManagedDevice   = [bool]($managementSignals.Count -gt 0)
        Domain            = [string]$computer.Domain
        TotalMemoryBytes  = [long]$computer.TotalPhysicalMemory
        ProcessorCount    = [int]$computer.NumberOfLogicalProcessors
        HasBattery        = [bool]$powerSafety.HasBattery
        BatteryDetectionReliable = [bool]$powerSafety.BatteryDetectionReliable
        AcLineStatus      = [string]$powerSafety.AcLineStatus
        AcLineStatusReliable = [bool]$powerSafety.AcLineStatusReliable
        BatteryLifePercent = [int]$powerSafety.BatteryLifePercent
    }
}

function Get-MaintenanceSafetyState {
    [CmdletBinding()]
    param()

    $reasons = New-Object System.Collections.ArrayList
    try {
        $cbsPending = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $wuPending = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $cbsPending -ErrorAction Stop) {
            [void]$reasons.Add('Component Based Servicing reports a pending reboot.')
        }
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $wuPending -ErrorAction Stop) {
            [void]$reasons.Add('Windows Update reports a pending reboot.')
        }

        $sessionManagerPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
        $sessionManager = Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $sessionManagerPath -ErrorAction Stop
        $pendingRenameProperty = $sessionManager.PSObject.Properties['PendingFileRenameOperations']
        if ($null -ne $pendingRenameProperty -and @($pendingRenameProperty.Value).Count -gt 0) {
            [void]$reasons.Add('Windows reports pending file rename/delete operations.')
        }

        $activeMaintenanceServices = @(CimCmdlets\Get-CimInstance -ClassName Win32_Service `
            -Filter "(Name='TrustedInstaller' OR Name='msiserver') AND State='Running'" -ErrorAction Stop)
        if ($activeMaintenanceServices.Count -gt 0) {
            [void]$reasons.Add('Windows servicing or Windows Installer is active.')
        }

        $activeMaintenanceProcesses = @(CimCmdlets\Get-CimInstance -ClassName Win32_Process `
            -Filter "Name='TiWorker.exe' OR Name='TrustedInstaller.exe' OR Name='msiexec.exe' OR Name='dism.exe'" -ErrorAction Stop)
        if ($activeMaintenanceProcesses.Count -gt 0) {
            [void]$reasons.Add('A servicing, installer, or DISM process is active.')
        }

        return [pscustomobject][ordered]@{
            DetectionReliable = $true
            Safe              = ($reasons.Count -eq 0)
            Reasons           = @($reasons)
            Error             = $null
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            DetectionReliable = $false
            Safe              = $false
            Reasons           = @('Maintenance-state detection was incomplete.')
            Error             = $_.Exception.Message
        }
    }
}

function Get-MaintenanceBlockMessage {
    [CmdletBinding()]
    param()

    $state = Get-MaintenanceSafetyState
    if ($state.Safe) { return $null }
    if (-not $state.DetectionReliable) {
        Write-Log -Level 'DEBUG' -Message ("Maintenance-state detection error: {0}" -f $state.Error) -NoConsole
    }
    return ("Maintenance operation was refused: {0} Finish servicing/installations and restart Windows if pending, then audit again." -f ($state.Reasons -join ' '))
}

function Get-LongMaintenancePowerBlockMessage {
    [CmdletBinding()]
    param()

    try {
        $state = Get-SystemPowerSafetyState
    }
    catch {
        return 'Long-running maintenance was refused because battery/power-source status could not be verified. Connect stable AC power and retry.'
    }
    if (-not $state.BatteryDetectionReliable) {
        return 'Long-running maintenance was refused because battery presence could not be determined reliably.'
    }
    if ($state.HasBattery -and (-not $state.AcLineStatusReliable -or $state.AcLineStatus -cne 'Online')) {
        return 'Long-running maintenance was refused on a battery-powered device that is not verifiably connected to AC power.'
    }
    return $null
}

function Get-Windows10PowerPlanBlockMessage {
    [CmdletBinding()]
    param()

    try {
        $state = Get-SystemPowerSafetyState
    }
    catch {
        return 'Windows 10 power-plan mutation was refused because battery/power-source status could not be verified.'
    }
    if (-not $state.BatteryDetectionReliable) {
        return 'Windows 10 power-plan mutation was refused because battery presence could not be determined reliably.'
    }
    if ($state.HasBattery) {
        if (-not $state.AcLineStatusReliable -or $state.AcLineStatus -cne 'Online') {
            return 'Windows 10 power-plan mutation on a battery-equipped device requires a verified AC connection.'
        }
        if (-not $AcknowledgeBatteryPowerPlan) {
            return 'Windows 10 power-plan mutation on a battery-equipped device requires -AcknowledgeBatteryPowerPlan because the active plan also governs battery/DC behavior.'
        }
    }
    return $null
}

function New-Operation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Id,
        [Parameter(Mandatory = $true)] [string]$Category,
        [Parameter(Mandatory = $true)] [string]$DisplayName,
        [Parameter(Mandatory = $true)] [string]$Description,
        [Parameter(Mandatory = $true)] [string]$Impact,
        [Parameter(Mandatory = $true)] [ValidateSet('Low', 'Medium', 'High')] [string]$Risk,
        [Parameter(Mandatory = $true)] [bool]$Recommended,
        [Parameter(Mandatory = $true)] [bool]$Reversible,
        [Parameter(Mandatory = $true)] [string]$Kind,
        [bool]$BulkEligible = $true,
        [string]$Target,
        [string]$ServiceName
    )

    return [pscustomobject][ordered]@{
        Id          = $Id
        Category    = $Category
        DisplayName = $DisplayName
        Description = $Description
        Impact      = $Impact
        Risk        = $Risk
        Recommended = $Recommended
        Reversible  = $Reversible
        BulkEligible = $BulkEligible
        Kind        = $Kind
        Target      = $Target
        ServiceName = $ServiceName
    }
}

function Get-OptimizationCatalog {
    [CmdletBinding()]
    param()

    $catalog = New-Object System.Collections.ArrayList
    $trustedTempRoots = @(Get-TrustedTempRoots)
    $userTemp = @($trustedTempRoots | Where-Object { $_.Id -eq 'cleanup.user-temp' })
    $windowsTemp = @($trustedTempRoots | Where-Object { $_.Id -eq 'cleanup.windows-temp' })
    $tempRootsCoincide = $userTemp.Count -eq 1 -and $windowsTemp.Count -eq 1 -and
        $userTemp[0].Path -ieq $windowsTemp[0].Path

    if ($userTemp.Count -eq 1 -and -not $tempRootsCoincide) {
        [void]$catalog.Add((New-Operation -Id 'cleanup.user-temp' -Category 'Cleanup' `
            -DisplayName 'Clean current user temporary folder' `
            -Description ("Delete regular files last modified at least {0} day(s) ago; preserve every folder." -f $MinimumAgeDays) `
            -Impact 'Open/recent files, folders, and reparse points are preserved. Deleted files are not recoverable through this script.' `
            -Risk 'Low' -Recommended $true -Reversible $false -Kind 'TempFolder' -Target $userTemp[0].Path))
    }

    if ($windowsTemp.Count -eq 1) {
        [void]$catalog.Add((New-Operation -Id 'cleanup.windows-temp' -Category 'Cleanup' `
            -DisplayName 'Clean Windows temporary folder' `
            -Description ("Delete regular files last modified at least {0} day(s) ago; preserve every folder." -f $MinimumAgeDays) `
            -Impact 'Locked/recent files, folders, and reparse points are preserved. Deleted files are not recoverable through this script.' `
            -Risk 'Medium' -Recommended $false -Reversible $false -Kind 'TempFolder' -Target $windowsTemp[0].Path))
    }

    [void]$catalog.Add((New-Operation -Id 'storage.clear-delivery-optimization-cache' -Category 'Storage' `
        -DisplayName 'Clear Delivery Optimization cache' `
        -Description 'Use the supported Delivery Optimization cmdlet to remove unpinned cached update content.' `
        -Impact 'Windows may download the content again. This is primarily a disk-space action, not a routine speed boost.' `
        -Risk 'Low' -Recommended $false -Reversible $false -Kind 'DeliveryOptimization'))

    [void]$catalog.Add((New-Operation -Id 'storage.component-store-cleanup' -Category 'Storage' `
        -DisplayName 'Clean superseded component-store content' `
        -Description 'Analyze WinSxS with DISM, then run StartComponentCleanup. ResetBase is never used.' `
        -Impact 'Old superseded component versions are removed immediately; the operation can take considerable time.' `
        -Risk 'Medium' -Recommended $false -Reversible $false -Kind 'ComponentStore'))

    [void]$catalog.Add((New-Operation -Id 'storage.optimize-fixed-volumes' -Category 'Storage' `
        -DisplayName 'Optimize healthy fixed volumes' `
        -Description 'Let Optimize-Volume select the media-appropriate default operation for each fixed NTFS/ReFS volume.' `
        -Impact 'May run for a long time and create storage I/O. Windows normally schedules this maintenance automatically.' `
        -Risk 'Low' -Recommended $false -Reversible $false -Kind 'OptimizeVolumes'))

    [void]$catalog.Add((New-Operation -Id 'network.normalize-tcp-autotuning' -Category 'Network' `
        -DisplayName 'Normalize custom TCP receive-window auto-tuning' `
        -Description 'Set modifiable InternetCustom/DatacenterCustom templates to Normal only when not controlled by Group Policy.' `
        -Impact 'Can change throughput or compatibility on VPN/vendor/legacy networks; benchmark before and after.' `
        -Risk 'Medium' -Recommended $false -Reversible $true -Kind 'TcpAutoTuning'))

    [void]$catalog.Add((New-Operation -Id 'network.enable-rss-wired' -Category 'Network' `
        -DisplayName 'Enable RSS on supported wired physical adapters' `
        -Description 'Enable Receive Side Scaling only on RSS-capable physical Ethernet adapters where it is disabled.' `
        -Impact 'The adapter can restart, briefly interrupting network connectivity. Wireless adapters are excluded.' `
        -Risk 'Medium' -Recommended $false -Reversible $true -Kind 'Rss'))

    [void]$catalog.Add((New-Operation -Id 'power.best-performance-ac' -Category 'Power' `
        -DisplayName 'Use Best performance while connected to AC power' `
        -Description 'Windows 11: set the documented AC power-mode vote. Windows 10: activate an existing High performance plan only.' `
        -Impact 'Increases electricity use and heat. On Windows 10 laptops, the active plan also applies its configured battery values.' `
        -Risk 'Medium' -Recommended $false -Reversible $true -Kind 'PowerPerformance'))

    [void]$catalog.Add((New-Operation -Id 'ux.disable-client-area-animations' -Category 'UserExperience' `
        -DisplayName 'Disable client-area animations' `
        -Description 'Use the documented SystemParametersInfo API to turn off UI client-area animations.' `
        -Impact 'Reduces motion and may improve responsiveness on lower-powered PCs. Changes the current user only.' `
        -Risk 'Low' -Recommended $false -Reversible $true -Kind 'ClientAnimations'))

    [void]$catalog.Add((New-Operation -Id 'startup.review-apps' -Category 'Startup' `
        -DisplayName 'Review startup applications' `
        -Description 'Capture startup entries in the audit report and open the supported Startup Apps settings page.' `
        -Impact 'No entries are changed automatically; the signed-in user decides which applications to disable.' `
        -Risk 'Low' -Recommended $false -Reversible $false -Kind 'OpenStartupApps'))

    [void]$catalog.Add((New-Operation -Id 'storage.review-storage-sense' -Category 'Storage' `
        -DisplayName 'Review Storage Sense configuration' `
        -Description 'Open the supported Storage Sense settings page for user-controlled cleanup scheduling.' `
        -Impact 'The script does not enable Downloads cleanup or cloud-content dehydration automatically.' `
        -Risk 'Low' -Recommended $false -Reversible $false -Kind 'OpenStorageSense'))

    $serviceDefinitions = @(
        @{ Name = 'RetailDemo';       Label = 'Retail Demo Service';                     Feature = 'retail demonstration mode'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'Fax';              Label = 'Fax';                                     Feature = 'Windows fax sending and receiving'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'wisvc';            Label = 'Windows Insider Service';                 Feature = 'Windows Insider enrollment and preview builds'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'MapsBroker';       Label = 'Downloaded Maps Manager';                 Feature = 'downloaded and offline maps'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'WMPNetworkSvc';    Label = 'Windows Media Player Network Sharing';    Feature = 'media-library sharing to network players'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'icssvc';           Label = 'Windows Mobile Hotspot Service';          Feature = 'mobile hotspot and cellular connection sharing'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'SEMgrSvc';         Label = 'Payments and NFC/SE Manager';             Feature = 'NFC payments and secure-element features'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'WalletService';    Label = 'Wallet Service';                          Feature = 'Windows wallet integrations'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'XboxGipSvc';       Label = 'Xbox Accessory Management Service';       Feature = 'Xbox controllers, including adaptive or accessibility input hardware'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'XblAuthManager';   Label = 'Xbox Live Auth Manager';                  Feature = 'Xbox Live sign-in and dependent apps'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'XblGameSave';      Label = 'Xbox Live Game Save';                     Feature = 'Xbox cloud-save synchronization'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'XboxNetApiSvc';    Label = 'Xbox Live Networking Service';            Feature = 'Xbox Live networking'; Risk = 'Low'; Bulk = $true },
        @{ Name = 'VacSvc';           Label = 'Volumetric Audio Compositor Service';     Feature = 'Mixed Reality spatial audio'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'spectrum';         Label = 'Windows Perception Service';              Feature = 'Mixed Reality spatial perception and holographic rendering'; Risk = 'Medium'; Bulk = $false },
        @{ Name = 'perceptionsimulation'; Label = 'Windows Perception Simulation Service'; Feature = 'Mixed Reality perception simulation'; Risk = 'Medium'; Bulk = $false }
    )

    foreach ($definition in $serviceDefinitions) {
        $serviceId = 'service.{0}' -f $definition.Name.ToLowerInvariant()
        [void]$catalog.Add((New-Operation -Id $serviceId -Category 'Services' `
            -DisplayName ("Disable {0}" -f $definition.Label) `
            -Description ("Disable the allowlisted service only if you do not use {0}." -f $definition.Feature) `
            -Impact ("The following feature will stop working until restored: {0}. A Manual/Stopped service already uses no active CPU." -f $definition.Feature) `
            -Risk $definition.Risk -Recommended $false -Reversible $true -Kind 'Service' `
            -BulkEligible ([bool]$definition.Bulk) -ServiceName $definition.Name))
    }

    return @($catalog)
}

function Get-RssCandidateAdapters {
    [CmdletBinding()]
    param()

    $queryFailures = New-Object System.Collections.ArrayList
    $script:LastRssCandidateDiagnostics = [pscustomobject][ordered]@{
        ModuleAvailable             = $false
        AdapterEnumerationSucceeded = $false
        RouteDetectionSucceeded     = $false
        QueryFailures               = $queryFailures
    }
    if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Get-NetAdapter' -ErrorAction SilentlyContinue) -or
        -not (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Get-NetAdapterRss' -ErrorAction SilentlyContinue)) {
        return @()
    }
    $script:LastRssCandidateDiagnostics.ModuleAvailable = $true

    $candidates = New-Object System.Collections.ArrayList
    $defaultRouteIndices = @()
    $routeDetectionSucceeded = $false
    if (Microsoft.PowerShell.Core\Get-Command -Name 'NetTCPIP\Get-NetRoute' -ErrorAction SilentlyContinue) {
        try {
            $defaultRouteIndices = @(NetTCPIP\Get-NetRoute -ErrorAction Stop | Where-Object {
                @('0.0.0.0/0', '::/0') -contains ([string]$_.DestinationPrefix)
            } | ForEach-Object { [int]$_.InterfaceIndex } | Select-Object -Unique)
            $routeDetectionSucceeded = $true
            $script:LastRssCandidateDiagnostics.RouteDetectionSucceeded = $true
        }
        catch {
            $routeDetectionSucceeded = $false
        }
    }
    $adapters = @(NetAdapter\Get-NetAdapter -ErrorAction Stop | Where-Object {
        $_.HardwareInterface -eq $true -and $_.Status -ne 'Disabled'
    })
    $script:LastRssCandidateDiagnostics.AdapterEnumerationSucceeded = $true

    foreach ($adapter in $adapters) {
        $physicalMedia = [string]$adapter.PhysicalMediaType
        $media = [string]$adapter.MediaType
        $description = [string]$adapter.InterfaceDescription
        $isWired = ($physicalMedia -match '802\.3|Ethernet') -or
                   ($media -match '802\.3|Ethernet') -or
                   ($description -match 'Ethernet' -and $description -notmatch 'Wireless|Wi-?Fi|802\.11')
        if (-not $isWired) {
            continue
        }

        $interfaceGuid = [guid]::Empty
        $interfaceGuidText = [string]$adapter.InterfaceGuid
        if (-not [guid]::TryParse($interfaceGuidText, [ref]$interfaceGuid) -or $interfaceGuid -eq [guid]::Empty) {
            [void]$queryFailures.Add([pscustomobject]@{
                InterfaceGuid = $interfaceGuidText
                Error = 'Adapter reported a missing or invalid interface GUID.'
            })
            continue
        }

        try {
            $rss = $adapter | NetAdapter\Get-NetAdapterRss -ErrorAction Stop
            if ($null -ne $rss) {
                [void]$candidates.Add([pscustomobject][ordered]@{
                    Name                 = [string]$adapter.Name
                    InterfaceGuid        = $interfaceGuid.ToString()
                    InterfaceIndex       = [int]$adapter.InterfaceIndex
                    InterfaceDescription = [string]$adapter.InterfaceDescription
                    Status               = [string]$adapter.Status
                    IsDefaultRoute        = if ($routeDetectionSucceeded) { ($defaultRouteIndices -contains [int]$adapter.InterfaceIndex) } else { $null }
                    Enabled              = [bool]$rss.Enabled
                })
            }
        }
        catch {
            [void]$queryFailures.Add([pscustomobject]@{
                InterfaceGuid = $interfaceGuid.ToString()
                Error = $_.Exception.Message
            })
        }
    }

    return @($candidates)
}

function Get-ExistingHighPerformancePlan {
    [CmdletBinding()]
    param()

    $highPerformanceGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    $powercfgPath = Get-TrustedSystemExecutable -Name 'powercfg.exe'
    $output = @(& $powercfgPath /list 2>&1)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $joined = $output -join [Environment]::NewLine
    if ($joined -match [regex]::Escape($highPerformanceGuid)) {
        return $highPerformanceGuid
    }

    return $null
}

function Get-ActivePowerPlanGuid {
    [CmdletBinding()]
    param()

    $powercfgPath = Get-TrustedSystemExecutable -Name 'powercfg.exe'
    $output = @(& $powercfgPath /getactivescheme 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ("powercfg /getactivescheme failed: {0}" -f ($output -join ' '))
    }

    $match = [regex]::Match(($output -join ' '), '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    if (-not $match.Success) {
        throw 'The active power-plan GUID could not be parsed.'
    }

    return $match.Value.ToLowerInvariant()
}

function Get-OperationAvailability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Operation,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$OsInfo
    )

    try {
        $hasInteractiveUserContext = Test-IsInteractiveUserContext -UserSid ([string]$OsInfo.CurrentUserSid)
        switch ($Operation.Kind) {
            'TempFolder' {
                if (-not $hasInteractiveUserContext -and $Operation.Id -eq 'cleanup.user-temp') {
                    return [pscustomobject]@{ Available = $false; Reason = 'Current-user Temp cleanup requires an interactive signed-in user context; service and Session-0 accounts are refused.' }
                }
                if (-not (Test-Path -LiteralPath $Operation.Target -PathType Container)) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Folder is not present.' }
                }
                if (Test-IsUnsafeCleanupRoot -Path $Operation.Target) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Resolved path failed the cleanup safety policy.' }
                }
                if (Test-PathContainsReparsePoint -Path $Operation.Target) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Cleanup target or a parent is a reparse point; traversal was refused.' }
                }
                $scriptRootFull = Get-SafeFullPath -Path $PSScriptRoot
                $targetFull = Get-SafeFullPath -Path $Operation.Target
                if ($scriptRootFull -ieq $targetFull -or $scriptRootFull.StartsWith($targetFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                    return [pscustomobject]@{ Available = $false; Reason = 'The script is running from inside this Temp folder. Move it before cleanup.' }
                }
                return [pscustomobject]@{ Available = $true; Reason = 'Available' }
            }
            'DeliveryOptimization' {
                $present = $null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'DeliveryOptimization\Delete-DeliveryOptimizationCache' -ErrorAction SilentlyContinue)
                return [pscustomobject]@{ Available = $present; Reason = $(if ($present) { 'Available' } else { 'Delivery Optimization cmdlet is unavailable.' }) }
            }
            'ComponentStore' {
                $present = $null -ne (Get-TrustedSystemExecutable -Name 'Dism.exe' -Optional)
                return [pscustomobject]@{ Available = $present; Reason = $(if ($present) { 'Available' } else { 'DISM is unavailable.' }) }
            }
            'OptimizeVolumes' {
                $present = $null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'Storage\Optimize-Volume' -ErrorAction SilentlyContinue)
                return [pscustomobject]@{ Available = $present; Reason = $(if ($present) { 'Available' } else { 'Storage cmdlets are unavailable.' }) }
            }
            'TcpAutoTuning' {
                $present = ($null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'NetTCPIP\Get-NetTCPSetting' -ErrorAction SilentlyContinue)) -and
                           ($null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'NetTCPIP\Set-NetTCPSetting' -ErrorAction SilentlyContinue))
                return [pscustomobject]@{ Available = $present; Reason = $(if ($present) { 'Available' } else { 'NetTCPIP cmdlets are unavailable.' }) }
            }
            'Rss' {
                $present = ($null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Enable-NetAdapterRss' -ErrorAction SilentlyContinue)) -and
                           ($null -ne (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Disable-NetAdapterRss' -ErrorAction SilentlyContinue))
                if (-not $present) {
                    return [pscustomobject]@{ Available = $false; Reason = 'NetAdapter RSS cmdlets are unavailable.' }
                }
                if (@(Get-RssCandidateAdapters).Count -eq 0) {
                    return [pscustomobject]@{ Available = $false; Reason = 'No supported wired physical RSS adapter was found.' }
                }
                return [pscustomobject]@{ Available = $true; Reason = 'Available' }
            }
            'PowerPerformance' {
                if (-not $hasInteractiveUserContext) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Power preference requires an interactive signed-in user context; service and Session-0 accounts are refused.' }
                }
                if ($OsInfo.Family -eq 'Windows 11') {
                    Initialize-NativeMethods
                    [void]$script:NativeMethods.GetACPowerMode()
                    return [pscustomobject]@{ Available = $true; Reason = 'Windows 11 AC power-mode API is available.' }
                }
                $plan = Get-ExistingHighPerformancePlan
                return [pscustomobject]@{ Available = ($null -ne $plan); Reason = $(if ($null -ne $plan) { 'Existing High performance plan is available.' } else { 'No existing High performance plan is available; the script will not create or force one.' }) }
            }
            'ClientAnimations' {
                if (-not $hasInteractiveUserContext) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Client-area animations require an interactive signed-in user context; service and Session-0 accounts are refused.' }
                }
                Initialize-NativeMethods
                [void]$script:NativeMethods.GetClientAreaAnimation()
                return [pscustomobject]@{ Available = $true; Reason = 'Available' }
            }
            'OpenStartupApps' {
                if (-not $hasInteractiveUserContext) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Startup Apps settings requires an interactive signed-in user context.' }
                }
                return [pscustomobject]@{ Available = $true; Reason = 'Available' }
            }
            'OpenStorageSense' {
                if (-not $hasInteractiveUserContext) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Storage Sense settings requires an interactive signed-in user context.' }
                }
                return [pscustomobject]@{ Available = $true; Reason = 'Available' }
            }
            'Service' {
                if ($script:CriticalServiceDenylist -icontains $Operation.ServiceName) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Service is on the critical denylist.' }
                }
                $service = Microsoft.PowerShell.Management\Get-Service -Name $Operation.ServiceName -ErrorAction SilentlyContinue
                if ($null -eq $service) {
                    return [pscustomobject]@{ Available = $false; Reason = 'Service is not installed on this Windows edition.' }
                }
                [void](Get-ServiceBeforeState -Name $Operation.ServiceName)
                return [pscustomobject]@{ Available = $true; Reason = 'Microsoft Windows service identity verified.' }
            }
            default {
                return [pscustomobject]@{ Available = $false; Reason = 'Unknown operation kind.' }
            }
        }
    }
    catch {
        return [pscustomobject]@{ Available = $false; Reason = ("Availability check failed: {0}" -f $_.Exception.Message) }
    }
}

function Get-SelectedOperations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object[]]$Catalog
    )

    $selectedIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $hasSelector = $false

    if ($AllRecommended) {
        $hasSelector = $true
        foreach ($operation in $Catalog | Where-Object { $_.Recommended }) {
            [void]$selectedIds.Add($operation.Id)
        }
    }

    if ($null -ne $Category -and @($Category).Count -gt 0) {
        $hasSelector = $true
        foreach ($operation in $Catalog | Where-Object {
            $Category -icontains $_.Category -and
            ($Mode -eq 'Audit' -or $_.Category -ne 'Services' -or $_.BulkEligible)
        }) {
            [void]$selectedIds.Add($operation.Id)
        }
    }

    if ($CleanUserTemp) {
        $hasSelector = $true
        if (@($Catalog | Where-Object { $_.Id -eq 'cleanup.user-temp' }).Count -eq 1) {
            [void]$selectedIds.Add('cleanup.user-temp')
        }
        else {
            $trustedRoots = @(Get-TrustedTempRoots)
            $trustedUserRoot = @($trustedRoots | Where-Object { $_.Id -eq 'cleanup.user-temp' })
            $trustedWindowsRoot = @($trustedRoots | Where-Object { $_.Id -eq 'cleanup.windows-temp' })
            $strictSharedOperation = @($Catalog | Where-Object { $_.Id -eq 'cleanup.windows-temp' })
            if ($trustedUserRoot.Count -eq 1 -and $trustedWindowsRoot.Count -eq 1 -and
                $trustedUserRoot[0].Path -ieq $trustedWindowsRoot[0].Path -and $strictSharedOperation.Count -eq 1) {
                [void]$selectedIds.Add('cleanup.windows-temp')
            }
            else {
                throw 'The canonical current-user Temp folder could not be resolved.'
            }
        }
    }
    if ($CleanWindowsTemp) {
        $hasSelector = $true
        if (@($Catalog | Where-Object { $_.Id -eq 'cleanup.windows-temp' }).Count -ne 1) {
            throw 'The canonical Windows Temp folder could not be resolved.'
        }
        [void]$selectedIds.Add('cleanup.windows-temp')
    }
    if ($ClearDeliveryOptimizationCache)   { $hasSelector = $true; [void]$selectedIds.Add('storage.clear-delivery-optimization-cache') }
    if ($RunComponentCleanup)              { $hasSelector = $true; [void]$selectedIds.Add('storage.component-store-cleanup') }
    if ($OptimizeFixedVolumes)             { $hasSelector = $true; [void]$selectedIds.Add('storage.optimize-fixed-volumes') }
    if ($null -ne $VolumeDriveLetter -and @($VolumeDriveLetter).Count -gt 0) {
        $hasSelector = $true
        [void]$selectedIds.Add('storage.optimize-fixed-volumes')
    }
    if ($NormalizeTcpAutoTuning)           { $hasSelector = $true; [void]$selectedIds.Add('network.normalize-tcp-autotuning') }
    if ($EnableReceiveSideScaling)         { $hasSelector = $true; [void]$selectedIds.Add('network.enable-rss-wired') }
    if ($null -ne $AdapterInterfaceGuid -and @($AdapterInterfaceGuid).Count -gt 0) {
        $hasSelector = $true
        [void]$selectedIds.Add('network.enable-rss-wired')
    }
    if ($SetBestPerformancePowerMode)      { $hasSelector = $true; [void]$selectedIds.Add('power.best-performance-ac') }
    if ($DisableClientAnimations)          { $hasSelector = $true; [void]$selectedIds.Add('ux.disable-client-area-animations') }
    if ($ReviewStartupApps)                { $hasSelector = $true; [void]$selectedIds.Add('startup.review-apps') }
    if ($ReviewStorageSense)               { $hasSelector = $true; [void]$selectedIds.Add('storage.review-storage-sense') }
    if ($DisableOptionalServices) {
        $hasSelector = $true
        foreach ($operation in $Catalog | Where-Object { $_.Kind -eq 'Service' -and $_.BulkEligible }) {
            [void]$selectedIds.Add($operation.Id)
        }
    }

    if ($null -ne $ServiceName -and @($ServiceName).Count -gt 0) {
        $hasSelector = $true
        foreach ($requestedService in $ServiceName) {
            if ($script:CriticalServiceDenylist -icontains $requestedService) {
                throw ("Service '{0}' is protected by the critical-service denylist and cannot be selected." -f $requestedService)
            }
            $match = @($Catalog | Where-Object { $_.Kind -eq 'Service' -and $_.ServiceName -ieq $requestedService })
            if ($match.Count -ne 1) {
                throw ("Service '{0}' is not in the conservative service allowlist. Use -ListOptimizations." -f $requestedService)
            }
            [void]$selectedIds.Add($match[0].Id)
        }
    }

    if ($null -ne $IncludeOptimization -and @($IncludeOptimization).Count -gt 0) {
        $hasSelector = $true
        foreach ($requestedId in $IncludeOptimization) {
            if (@($Catalog | Where-Object { $_.Id -ieq $requestedId }).Count -ne 1) {
                throw ("Unknown optimization ID '{0}'. Use -ListOptimizations." -f $requestedId)
            }
            [void]$selectedIds.Add($requestedId)
        }
    }

    if (-not $hasSelector) {
        if ($Mode -eq 'Apply') {
            throw 'Apply mode requires a selector. Use -AllRecommended, -Category, an individual switch, -ServiceName, or -IncludeOptimization.'
        }
        foreach ($operation in $Catalog) {
            [void]$selectedIds.Add($operation.Id)
        }
    }

    if ($null -ne $ExcludeOptimization) {
        foreach ($excludedId in $ExcludeOptimization) {
            if (@($Catalog | Where-Object { $_.Id -ieq $excludedId }).Count -ne 1) {
                throw ("Unknown exclusion ID '{0}'. Use -ListOptimizations." -f $excludedId)
            }
            [void]$selectedIds.Remove($excludedId)
        }
    }

    return @($Catalog | Where-Object { $selectedIds.Contains($_.Id) })
}

function Request-OperationConsent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation,
        [string]$AdditionalContext,
        [ValidateSet('Apply', 'Restore')] [string]$Purpose = 'Apply'
    )

    if ($ConsentPolicy -eq 'NoToAll') {
        Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: declined by NoToAll policy." -f $Purpose, $Operation.Id)
        return $false
    }
    if ($ConsentPolicy -eq 'Recommended' -and -not $Operation.Recommended) {
        Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: declined because it is not recommended." -f $Purpose, $Operation.Id)
        return $false
    }

    $automaticApproval = @('YesToAll', 'Recommended') -contains $ConsentPolicy
    $isIrreversibleMutation = -not $Operation.Reversible -and @(
        'TempFolder', 'DeliveryOptimization', 'ComponentStore', 'OptimizeVolumes'
    ) -contains ([string]$Operation.Kind)
    if (-not $script:IsWhatIf -and $isIrreversibleMutation -and $automaticApproval -and
        -not $AcknowledgeIrreversibleActions) {
        throw ("Automatic consent for irreversible operation '{0}' requires -AcknowledgeIrreversibleActions." -f $Operation.Id)
    }
    if (-not $script:IsWhatIf -and $Operation.Kind -eq 'TempFolder' -and $MinimumAgeDays -eq 0 -and
        -not $AcknowledgeDeleteAllTempAges) {
        throw 'MinimumAgeDays 0 requires -AcknowledgeDeleteAllTempAges for temporary-file cleanup.'
    }

    switch ($ConsentPolicy) {
        'YesToAll' {
            Write-Log -Level 'WARN' -Message ("{0} consent decision for {1}: approved automatically by YesToAll policy." -f $Purpose, $Operation.Id)
            return $true
        }
        'Recommended' {
            Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: approved automatically as a recommended operation." -f $Purpose, $Operation.Id)
            return $true
        }
    }

    # WhatIf must remain non-interactive, but explicit consent policies above still apply.
    if ($script:IsWhatIf) {
        Write-Log -Level 'DEBUG' -Message ("{0} consent decision for {1}: simulated approval under WhatIf." -f $Purpose, $Operation.Id) -NoConsole
        return $true
    }

    if ($NonInteractive) {
        throw 'ConsentPolicy Ask cannot be used with -NonInteractive. Choose Recommended, YesToAll, or NoToAll.'
    }

    $group = '{0}|{1}' -f $Operation.Category, $Operation.Risk
    if ($script:ConsentAllByGroup.ContainsKey($group) -and $script:ConsentAllByGroup[$group]) {
        Write-Log -Level 'WARN' -Message ("{0} consent decision for {1}: approved by prior category/risk-scoped A response." -f $Purpose, $Operation.Id)
        return $true
    }

    Write-Host ''
    if ($Purpose -eq 'Restore' -and $Operation.Kind -eq 'Service') {
        Write-UiHost -Message ("Restore Service? {0} ({1})" -f $Operation.DisplayName.Replace('Disable ', ''), $Operation.ServiceName) -Color Yellow
    }
    elseif ($Purpose -eq 'Restore') {
        Write-UiHost -Message ("Restore saved state? {0}" -f $Operation.DisplayName) -Color Yellow
    }
    elseif ($Operation.Kind -eq 'Service') {
        Write-UiHost -Message ("Disable Service? {0} ({1})" -f $Operation.DisplayName.Replace('Disable ', ''), $Operation.ServiceName) -Color Yellow
    }
    elseif ($Operation.Kind -eq 'TempFolder') {
        Write-UiHost -Message ("Delete eligible contents from temporary folder? {0}" -f $Operation.Target) -Color Yellow
        Write-UiHost -Message 'This is one confirmation for the folder; there will be no per-file prompts.' -Color DarkGray
    }
    else {
        Write-UiHost -Message ("Run optimization? {0}" -f $Operation.DisplayName) -Color Yellow
    }

    Write-Host ("Risk: {0} | Reversible by JSON restore: {1}" -f $Operation.Risk, $Operation.Reversible)
    if ($Purpose -eq 'Restore') {
        Write-Host 'Details: Restore the authenticated state captured immediately before this optimization was applied.'
        Write-Host 'Impact: This may re-enable a feature or revert a network, power, or user-experience preference.'
    }
    else {
        Write-Host ("Details: {0}" -f $Operation.Description)
        Write-Host ("Impact: {0}" -f $Operation.Impact)
    }
    if (-not [string]::IsNullOrWhiteSpace($AdditionalContext)) {
        Write-Host ("Current state: {0}" -f $AdditionalContext)
    }

    while ($true) {
        $answer = (Read-Host ("[Y] Yes  [N] No  [A] All remaining {0}-risk items in this category" -f $Operation.Risk)).Trim().ToUpperInvariant()
        switch ($answer) {
            'Y'   { Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: approved interactively." -f $Purpose, $Operation.Id); return $true }
            'YES' { Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: approved interactively." -f $Purpose, $Operation.Id); return $true }
            'N'   { Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: declined interactively." -f $Purpose, $Operation.Id); return $false }
            'NO'  { Write-Log -Level 'INFO' -Message ("{0} consent decision for {1}: declined interactively." -f $Purpose, $Operation.Id); return $false }
            'A' {
                $script:ConsentAllByGroup[$group] = $true
                Write-Log -Level 'WARN' -Message ("User approved all remaining items in consent group '{0}'." -f $group)
                return $true
            }
            default { Write-UiHost -Message 'Please enter Y, N, or A.' -Color Yellow }
        }
    }
}

function Get-ManifestKeyBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$KeyId,
        [switch]$CreateIfMissing
    )

    $parsedKeyId = [guid]::Empty
    if (-not [guid]::TryParse($KeyId, [ref]$parsedKeyId) -or $parsedKeyId -eq [guid]::Empty) {
        throw 'Rollback manifest key identity is invalid.'
    }

    $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($commonData)) {
        throw 'The Windows CommonApplicationData known folder could not be resolved.'
    }
    $adminRoot = Initialize-SecureDataRoot -Path (Join-Path $commonData $script:ScriptName)
    $keyDirectory = Join-Path $adminRoot 'Keys'
    New-SafeDirectory -Path $keyDirectory
    if (Test-PathContainsReparsePoint -Path $keyDirectory) {
        throw 'Rollback key directory or one of its parents is a reparse point.'
    }
    Set-RestrictedDirectoryAcl -Path $keyDirectory

    $keyPath = Join-Path $keyDirectory ("{0}.key" -f $parsedKeyId.ToString())
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        if (-not $CreateIfMissing) {
            throw 'The authentication key for this rollback manifest is unavailable.'
        }

        [byte[]]$newKey = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($newKey) } finally { $rng.Dispose() }

        $stream = [IO.File]::Open($keyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($newKey, 0, $newKey.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Set-RestrictedFileAcl -Path $keyPath
    }

    if (Test-PathContainsReparsePoint -Path $keyPath) {
        throw 'Rollback authentication key or one of its parents is a reparse point.'
    }
    Assert-ExistingRestrictedFileAcl -Path $keyPath
    [byte[]]$keyBytes = [IO.File]::ReadAllBytes($keyPath)
    if ($keyBytes.Length -ne 32) {
        throw 'Rollback authentication key has an invalid length.'
    }
    return $keyBytes
}

function Get-HmacSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [byte[]]$Key,
        [Parameter(Mandatory = $true)] [byte[]]$Data
    )

    $hmac = New-Object Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $Key
        return [byte[]]($hmac.ComputeHash($Data))
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-FixedTimeEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [byte[]]$Left,
        [Parameter(Mandatory = $true)] [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    $difference = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $difference = $difference -bor ($Left[$index] -bxor $Right[$index])
    }
    return ($difference -eq 0)
}

function Write-ManifestEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$PreservePreviousGeneration
    )

    $Path = Assert-SafeOperationalFilePath -Path $Path -Purpose 'Rollback manifest path'
    $keyId = [string]$Manifest.SessionId
    [byte[]]$key = Get-ManifestKeyBytes -KeyId $keyId -CreateIfMissing
    $payloadJson = $Manifest | ConvertTo-Json -Depth 16
    [byte[]]$payloadBytes = [Text.Encoding]::UTF8.GetBytes($payloadJson)
    [byte[]]$digest = Get-HmacSha256 -Key $key -Data $payloadBytes
    $envelope = [pscustomobject][ordered]@{
        EnvelopeVersion = $script:ManifestEnvelopeVersion
        ScriptName      = $script:ScriptName
        KeyId           = $keyId
        PayloadBase64   = [Convert]::ToBase64String($payloadBytes)
        HmacSha256      = [Convert]::ToBase64String($digest)
    }

    $temporaryPath = '{0}.{1}.tmp' -f $Path, ([guid]::NewGuid().ToString('N'))
    $backupGenerationPath = '{0}.{1}.bak' -f $Path, ([guid]::NewGuid().ToString('N'))
    $previousPath = '{0}.previous' -f $Path
    [void](Assert-SafeOperationalFilePath -Path $temporaryPath -Purpose 'Temporary rollback-manifest path')
    [void](Assert-SafeOperationalFilePath -Path $backupGenerationPath -Purpose 'Rollback-manifest rotation path')
    [void](Assert-SafeOperationalFilePath -Path $previousPath -Purpose 'Previous rollback-manifest path')
    try {
        $envelopeJson = $envelope | ConvertTo-Json -Depth 4
        Write-NewRestrictedTextFile -Path $temporaryPath -Text $envelopeJson
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            if (Test-PathContainsReparsePoint -Path $Path) {
                throw 'Rollback manifest or one of its parents is a reparse point.'
            }
            Assert-ExistingRestrictedFileAcl -Path $Path
            if (Test-Path -LiteralPath $previousPath) {
                if (Test-PathContainsReparsePoint -Path $previousPath) {
                    throw 'Previous rollback-manifest generation is a reparse point.'
                }
                Assert-ExistingRestrictedFileAcl -Path $previousPath
            }

            # Publish the new primary atomically before rotating the older
            # primary. A crash cannot leave both generations half-written.
            [IO.File]::Replace($temporaryPath, $Path, $backupGenerationPath, $true)
            Set-RestrictedFileAcl -Path $Path
            Set-RestrictedFileAcl -Path $backupGenerationPath

            if (-not $PreservePreviousGeneration) {
                try {
                    if (Test-Path -LiteralPath $previousPath -PathType Leaf) {
                        [IO.File]::Replace($backupGenerationPath, $previousPath, $null, $true)
                    }
                    else {
                        [IO.File]::Move($backupGenerationPath, $previousPath)
                    }
                    Set-RestrictedFileAcl -Path $previousPath
                }
                catch {
                    # The authenticated primary is already durable. Retain an
                    # older valid .previous generation and report rotation trouble.
                    Write-Log -Level 'WARN' -Message ("Rollback generation rotation was incomplete: {0}" -f $_.Exception.Message)
                }
            }
            else {
                # The restore was recovered from the authenticated .previous
                # generation. Do not replace that last-known-good fallback with
                # the invalid primary that File.Replace just moved aside.
                Remove-Item -LiteralPath $backupGenerationPath -Force -Confirm:$false -WhatIf:$false -ErrorAction Stop
            }
        }
        else {
            [IO.File]::Move($temporaryPath, $Path)
            Set-RestrictedFileAcl -Path $Path
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $backupGenerationPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupGenerationPath -Force -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
        }
    }
}

function Read-ManifestEnvelope {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    try {
        $envelope = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([int]$envelope.EnvelopeVersion -ne $script:ManifestEnvelopeVersion -or
            [string]$envelope.ScriptName -cne $script:ScriptName) {
            throw 'Envelope identity or version is unsupported.'
        }
        $keyId = [string]$envelope.KeyId
        [byte[]]$payloadBytes = [Convert]::FromBase64String([string]$envelope.PayloadBase64)
        [byte[]]$claimedDigest = [Convert]::FromBase64String([string]$envelope.HmacSha256)
        [byte[]]$key = Get-ManifestKeyBytes -KeyId $keyId
        [byte[]]$actualDigest = Get-HmacSha256 -Key $key -Data $payloadBytes
        if (-not (Test-FixedTimeEqual -Left $actualDigest -Right $claimedDigest)) {
            throw 'Rollback manifest authentication failed.'
        }

        $payloadJson = [Text.Encoding]::UTF8.GetString($payloadBytes)
        $manifest = $payloadJson | ConvertFrom-Json -ErrorAction Stop
        if ([string]$manifest.SessionId -cne $keyId) {
            throw 'Rollback manifest key identity does not match its payload.'
        }
        return $manifest
    }
    catch {
        throw ("Backup manifest is invalid or unauthenticated: {0}" -f $_.Exception.Message)
    }
}

function Initialize-SessionManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo
    )

    $dataRoot = Get-DefaultDataRoot
    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $backupDirectory = Join-Path $dataRoot 'Backups'
        New-SafeDirectory -Path $backupDirectory
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $script:BackupPath = Join-Path $backupDirectory ("WinOptimize-backup-{0}.json" -f $stamp)
    }
    else {
        $script:BackupPath = Assert-SafeOperationalFilePath -Path $BackupPath -Purpose 'BackupPath'
        Assert-PathWithinDataRoot -Path $script:BackupPath -DataRoot $dataRoot -Purpose 'rollback manifest'
        if (Test-Path -LiteralPath $script:BackupPath -PathType Container) {
            throw 'BackupPath must be a file path, not a directory.'
        }
        $backupDirectory = Split-Path -Parent $script:BackupPath
        if ([string]::IsNullOrWhiteSpace($backupDirectory)) {
            throw 'BackupPath must include a valid parent directory.'
        }
        Assert-PathWithinDataRoot -Path $backupDirectory -DataRoot $dataRoot -Purpose 'rollback-manifest directory' -AllowEqual
        Assert-OperationalPathOutsideTempRoots -Path $script:BackupPath -Purpose 'Rollback manifest'
        New-SafeDirectory -Path $backupDirectory
    }

    $script:BackupPath = Assert-SafeOperationalFilePath -Path $script:BackupPath -Purpose 'Rollback manifest path'
    Assert-OperationalPathOutsideTempRoots -Path $script:BackupPath -Purpose 'Rollback manifest'
    if (Test-PathContainsReparsePoint -Path (Split-Path -Parent $script:BackupPath)) {
        throw 'Rollback-manifest directory or one of its parents is a reparse point.'
    }
    Set-RestrictedDirectoryAcl -Path (Split-Path -Parent $script:BackupPath)
    if (Test-Path -LiteralPath $script:BackupPath) {
        throw ("Refusing to overwrite an existing backup path: {0}" -f $script:BackupPath)
    }
    $reservedPreviousPath = '{0}.previous' -f $script:BackupPath
    [void](Assert-SafeOperationalFilePath -Path $reservedPreviousPath -Purpose 'Reserved previous rollback-manifest path')
    Assert-PathWithinDataRoot -Path $reservedPreviousPath -DataRoot $dataRoot -Purpose 'reserved previous rollback-manifest generation'
    Assert-OperationalPathOutsideTempRoots -Path $reservedPreviousPath -Purpose 'Reserved previous rollback-manifest generation'
    if (Test-Path -LiteralPath $reservedPreviousPath) {
        throw ("Refusing to overwrite the reserved previous-generation path: {0}" -f $reservedPreviousPath)
    }

    $script:Session = [pscustomobject][ordered]@{
        SchemaVersion = $script:SchemaVersion
        ScriptName    = $script:ScriptName
        ScriptVersion = $script:ScriptVersion
        SessionId     = [guid]::NewGuid().ToString()
        Mode          = 'Apply'
        Outcome       = 'Running'
        StartedUtc    = [DateTime]::UtcNow.ToString('o')
        CompletedUtc  = $null
        Machine       = [pscustomobject][ordered]@{
            ComputerName = $OsInfo.ComputerName
            UserSid      = $OsInfo.CurrentUserSid
            DeviceIdentityHash = $OsInfo.DeviceIdentityHash
            Caption      = $OsInfo.Caption
            Version      = $OsInfo.Version
            BuildNumber  = $OsInfo.BuildNumber
        }
        RollbackLimitations = @(
            'Deleted temporary files and caches cannot be restored by this manifest.',
            'DISM component-store cleanup cannot be reversed by this manifest.',
            'Volume optimization cannot be reversed and normally does not need reversal.',
            'A System Restore point is best-effort and is not a backup of personal files.'
        )
        Records = @()
    }

    Save-SessionManifest
}

function Save-SessionManifest {
    [CmdletBinding()]
    param()

    if ($null -eq $script:Session -or [string]::IsNullOrWhiteSpace([string]$script:BackupPath)) {
        return
    }

    Write-ManifestEnvelope -Manifest $script:Session -Path $script:BackupPath
}

function New-ChangeRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation,
        [Parameter(Mandatory = $false)] $BeforeState,
        [Parameter(Mandatory = $true)] [string]$RestoreKind
    )

    $record = [pscustomobject][ordered]@{
        Id           = $Operation.Id
        Category     = $Operation.Category
        DisplayName  = $Operation.DisplayName
        RestoreKind  = $RestoreKind
        Reversible   = [bool]$Operation.Reversible
        PreparedUtc  = [DateTime]::UtcNow.ToString('o')
        CompletedUtc = $null
        Status       = 'Prepared'
        BeforeState  = $BeforeState
        AfterState   = $null
        Message      = $null
    }

    $script:Session.Records += $record
    Save-SessionManifest
    return $record
}

function Complete-ChangeRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Record,
        [Parameter(Mandatory = $true)] [string]$Status,
        $AfterState,
        [string]$Message
    )

    $Record.Status = $Status
    $Record.AfterState = $AfterState
    $Record.Message = $Message
    $Record.CompletedUtc = [DateTime]::UtcNow.ToString('o')
    Save-SessionManifest
}

function Complete-ReversibleFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Record,
        [Parameter(Mandatory = $true)] [string]$PrimaryError,
        [Parameter(Mandatory = $true)] [string]$Kind,
        [Parameter(Mandatory = $false)] $BeforeState,
        [Parameter(Mandatory = $true)] [scriptblock]$RollbackAction,
        [Parameter(Mandatory = $true)] [scriptblock]$ReadCurrentState
    )

    $observed = $null
    try {
        & $RollbackAction
        $observed = & $ReadCurrentState
        if (-not (Test-RestoreStateEquivalent -Kind $Kind -Left $observed -Right $BeforeState) -or
            ($Kind -eq 'Service' -and -not (Test-ServiceIdentityFingerprintEquivalent -Left $observed -Right $BeforeState))) {
            throw 'Automatic rollback verification did not match the original state.'
        }
        $message = '{0} Automatic rollback succeeded and was verified.' -f $PrimaryError
        Complete-ChangeRecord -Record $Record -Status 'RolledBack' -AfterState $observed -Message $message
        return $message
    }
    catch {
        $rollbackError = $_.Exception.Message
        try { $observed = & $ReadCurrentState } catch { $observed = $null }
        $message = '{0} Automatic rollback failed or could not be verified: {1}' -f $PrimaryError, $rollbackError
        Complete-ChangeRecord -Record $Record -Status 'RollbackFailed' -AfterState $observed -Message $message
        return $message
    }
}

function ConvertTo-RestoreComparableJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Service', 'TcpAutoTuning', 'Rss', 'PowerPerformance', 'ClientAnimations')] [string]$Kind,
        [Parameter(Mandatory = $false)] $State
    )

    if ($null -eq $State) {
        return 'null'
    }

    $normalized = switch ($Kind) {
        'Service' {
            $serviceDllPath = if ($null -ne $State.Identity.ServiceDll) {
                ([string]$State.Identity.ServiceDll.Path).ToLowerInvariant()
            }
            else { $null }
            [pscustomobject][ordered]@{
                Name             = ([string]$State.Name).ToLowerInvariant()
                BinaryPathName   = [string]$State.BinaryPathName
                AccountName      = [string]$State.AccountName
                ServiceType      = [string]$State.ServiceType
                AccountSid       = [string]$State.Identity.AccountSid
                RegistryType     = [uint32]$State.Identity.RegistryType
                ExecutablePath   = ([string]$State.Identity.Image.Path).ToLowerInvariant()
                ServiceDllPath   = $serviceDllPath
                StartMode        = [string]$State.StartMode
                DelayedAutoStart = [bool]$State.DelayedAutoStart
                State            = [string]$State.State
                Started          = [bool]$State.Started
            }
        }
        'TcpAutoTuning' {
            @($State | ForEach-Object {
                [pscustomobject][ordered]@{
                    SettingName          = [string]$_.SettingName
                    AutoTuningLevelLocal = [string]$_.AutoTuningLevelLocal
                    PolicyManaged        = ([string]$_.AutoTuningLevelEffective -eq 'GroupPolicy')
                }
            } | Sort-Object SettingName)
        }
        'Rss' {
            @($State | ForEach-Object {
                [pscustomobject][ordered]@{
                    InterfaceGuid = ([guid]([string]$_.InterfaceGuid)).ToString()
                    Enabled       = [bool]$_.Enabled
                }
            } | Sort-Object InterfaceGuid)
        }
        'PowerPerformance' {
            [pscustomobject][ordered]@{
                Mechanism = [string]$State.Mechanism
                Guid      = ([guid]([string]$State.Guid)).ToString()
            }
        }
        'ClientAnimations' {
            [pscustomobject][ordered]@{ Enabled = [bool]$State.Enabled }
        }
    }

    return (ConvertTo-Json -InputObject $normalized -Compress -Depth 8)
}

function Test-RestoreStateEquivalent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Service', 'TcpAutoTuning', 'Rss', 'PowerPerformance', 'ClientAnimations')] [string]$Kind,
        [Parameter(Mandatory = $false)] $Left,
        [Parameter(Mandatory = $false)] $Right
    )

    return ((ConvertTo-RestoreComparableJson -Kind $Kind -State $Left) -ceq
            (ConvertTo-RestoreComparableJson -Kind $Kind -State $Right))
}

function Get-CurrentStateForRestoreRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo
    )

    switch ([string]$Record.RestoreKind) {
        'Service' {
            return (Get-ServiceBeforeState -Name ([string]$Record.BeforeState.Name))
        }
        'TcpAutoTuning' {
            $names = @($Record.BeforeState | ForEach-Object { [string]$_.SettingName })
            return @(Get-TcpAutoTuningState | Where-Object { $names -icontains $_.SettingName })
        }
        'Rss' {
            $guids = @($Record.BeforeState | ForEach-Object { [string]$_.InterfaceGuid })
            return @(Get-RssCandidateAdapters | Where-Object { $guids -icontains $_.InterfaceGuid })
        }
        'PowerPerformance' {
            return (Get-PowerPerformanceState -OsInfo $OsInfo)
        }
        'ClientAnimations' {
            Initialize-NativeMethods
            return [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
        }
        default {
            throw ("Unsupported restore kind '{0}'." -f $Record.RestoreKind)
        }
    }
}

function Test-ShouldProcessOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Target,
        [Parameter(Mandatory = $true)] [string]$Action
    )

    return $script:CmdletContext.ShouldProcess($Target, $Action)
}

function New-BestEffortRestorePoint {
    [CmdletBinding()]
    param()

    if ($SkipRestorePoint -or $script:IsWhatIf) {
        Write-Log -Level 'INFO' -Message 'System Restore point creation was skipped.'
        return
    }

    if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'Microsoft.PowerShell.Management\Checkpoint-Computer' -ErrorAction SilentlyContinue)) {
        Write-Log -Level 'WARN' -Message 'Checkpoint-Computer is unavailable; continuing with the JSON state backup.'
        return
    }

    try {
        Write-Log -Level 'INFO' -Message 'Attempting a System Restore point (Windows permits at most one per day).'
        Microsoft.PowerShell.Management\Checkpoint-Computer -Description ("WinOptimize {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log -Level 'SUCCESS' -Message 'System Restore point created.'
    }
    catch {
        Write-Log -Level 'WARN' -Message ("System Restore point was not created: {0} Continuing with the JSON state backup." -f $_.Exception.Message)
    }
}

function Ensure-BestEffortRestorePoint {
    [CmdletBinding()]
    param()

    if ($script:RestorePointAttempted) {
        return
    }
    $script:RestorePointAttempted = $true
    New-BestEffortRestorePoint
}

function Resolve-ServiceExecutablePath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$CommandLine)

    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ($expanded.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $expanded = $windowsDirectory + $expanded.Substring(11)
    }
    if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded -match '[\x00\r\n]') {
        throw 'The service ImagePath is empty or contains control characters.'
    }

    $candidate = $null
    if ($expanded[0] -eq '"') {
        $closingQuote = $expanded.IndexOf('"', 1)
        if ($closingQuote -le 1) {
            throw 'The service ImagePath contains an unterminated or empty quoted executable.'
        }
        $candidate = $expanded.Substring(1, $closingQuote - 1)
        $remainder = $expanded.Substring($closingQuote + 1)
        if ($remainder.Length -gt 0 -and -not [char]::IsWhiteSpace($remainder[0])) {
            throw 'The service ImagePath has ambiguous text after its quoted executable.'
        }
    }
    else {
        $match = [regex]::Match(
            $expanded,
            '^(?<Executable>[^\s"]+?\.exe)(?=\s|$)',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (-not $match.Success) {
            throw 'The service ImagePath is unquoted or ambiguous and could not be resolved safely.'
        }
        $candidate = $match.Groups['Executable'].Value
    }

    return (Resolve-ServiceComponentPath -Path $candidate -ExpectedExtension '.exe')
}

function Test-IsApprovedServiceComponentPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    $fullPath = Get-SafeFullPath -Path $Path
    if ($fullPath -notmatch '^[A-Za-z]:\\' -or $fullPath.Substring(2).Contains(':') -or
        $fullPath -match '[\x00-\x1f\*\?]') {
        return $false
    }

    $approvedRoots = New-Object System.Collections.ArrayList
    [void]$approvedRoots.Add((Get-SafeFullPath -Path ([Environment]::SystemDirectory)))
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        [void]$approvedRoots.Add((Get-SafeFullPath -Path ([IO.Path]::Combine($programFiles, 'Windows Media Player'))))
    }

    foreach ($approvedRoot in $approvedRoots) {
        if (Test-PathIsWithin -Path $fullPath -Root $approvedRoot) {
            return $true
        }
    }
    return $false
}

function Resolve-ServiceComponentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [ValidateSet('.exe', '.dll')] [string]$ExpectedExtension
    )

    $expanded = [Environment]::ExpandEnvironmentVariables($Path).Trim()
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ($expanded.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $expanded = $windowsDirectory + $expanded.Substring(11)
    }
    if ([string]::IsNullOrWhiteSpace($expanded) -or $expanded.Contains('%') -or $expanded -match '[\x00\r\n"\*\?]' -or
        $expanded -notmatch '^[A-Za-z]:\\' -or $expanded.Substring(2).Contains(':')) {
        throw 'A service component path is relative, device-based, streamed, wildcarded, or otherwise unsafe.'
    }

    $fullPath = Get-SafeFullPath -Path $expanded
    if ([IO.Path]::GetExtension($fullPath) -ine $ExpectedExtension) {
        throw ("A service component did not have the expected '{0}' extension." -f $ExpectedExtension)
    }
    if (-not (Test-IsApprovedServiceComponentPath -Path $fullPath)) {
        throw 'A service component is outside the approved System32/Windows Media Player roots.'
    }
    return $fullPath
}

function Get-VerifiedMicrosoftServiceComponent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [ValidateSet('.exe', '.dll')] [string]$ExpectedExtension
    )

    $fullPath = Resolve-ServiceComponentPath -Path $Path -ExpectedExtension $ExpectedExtension
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fullPath -PathType Leaf -ErrorAction Stop) -or
        (Test-PathContainsReparsePoint -Path $fullPath) -or
        (Get-DriveTypeForPath -Path $fullPath) -ne [IO.DriveType]::Fixed) {
        throw ("Service component '{0}' is not a regular, non-reparse file on a fixed local drive." -f $fullPath)
    }

    $hashBefore = Get-ServiceComponentHash -Path $fullPath
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction Stop
    $isOsBinaryProperty = $signature.PSObject.Properties['IsOSBinary']
    if ([string]$signature.Status -cne 'Valid' -or $null -eq $isOsBinaryProperty -or
        $isOsBinaryProperty.Value -isnot [bool] -or -not [bool]$isOsBinaryProperty.Value -or
        $null -eq $signature.SignerCertificate -or
        [string]$signature.SignerCertificate.Subject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw ("Service component '{0}' is not a valid Microsoft Windows OS binary." -f $fullPath)
    }

    $hashAfter = Get-ServiceComponentHash -Path $fullPath
    if ([string]$hashBefore.Sha256 -cne [string]$hashAfter.Sha256 -or
        [long]$hashBefore.Length -ne [long]$hashAfter.Length) {
        throw ("Service component '{0}' changed while its identity was being verified." -f $fullPath)
    }

    return [pscustomobject][ordered]@{
        Path             = $fullPath
        Sha256           = [string]$hashAfter.Sha256
        Length           = [long]$hashAfter.Length
        SignatureStatus  = [string]$signature.Status
        SignatureType    = [string]$signature.SignatureType
        IsOsBinary       = [bool]$isOsBinaryProperty.Value
        SignerThumbprint = ([string]$signature.SignerCertificate.Thumbprint).Replace(' ', '').ToLowerInvariant()
        SignerSubject    = [string]$signature.SignerCertificate.Subject
    }
}

function Get-ServiceComponentHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $hasher.ComputeHash($stream)
        $sha256 = ([BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
        $length = [long]$stream.Length
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }

    return [pscustomobject][ordered]@{
        Sha256 = $sha256
        Length = $length
    }
}

function Resolve-ServiceAccountSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$AccountName,
        [Parameter(Mandatory = $true)] [string]$ServiceName
    )

    if (@('LocalSystem', 'NT AUTHORITY\SYSTEM') -icontains $AccountName) { return 'S-1-5-18' }
    if (@('NT AUTHORITY\LocalService', 'NT AUTHORITY\LOCAL SERVICE') -icontains $AccountName) { return 'S-1-5-19' }
    if (@('NT AUTHORITY\NetworkService', 'NT AUTHORITY\NETWORK SERVICE') -icontains $AccountName) { return 'S-1-5-20' }

    $expectedVirtualAccount = 'NT SERVICE\{0}' -f $ServiceName
    if ($AccountName -ine $expectedVirtualAccount) {
        throw ("Service account '{0}' is not a permitted built-in or same-service virtual account." -f $AccountName)
    }
    $account = New-Object Security.Principal.NTAccount($AccountName)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier])
    if (-not $sid.Value.StartsWith('S-1-5-80-', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The service virtual account did not resolve to a service SID.'
    }
    return $sid.Value
}

function Get-ServiceIdentityEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Service,
        [Parameter(Mandatory = $true)] [string]$Name
    )

    if ($Name -notmatch '^[A-Za-z0-9_.-]{1,256}$' -or [string]$Service.Name -ine $Name) {
        throw 'The service name cannot be used safely for identity verification.'
    }
    $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}' -f $Name
    $registryType = [uint32](Microsoft.PowerShell.Management\Get-ItemPropertyValue -LiteralPath $registryPath -Name 'Type' -ErrorAction Stop)
    if (@([uint32]0x10, [uint32]0x20) -notcontains $registryType) {
        throw ("Service '{0}' is not an ordinary Win32 own/share-process service." -f $Name)
    }

    $accountSid = Resolve-ServiceAccountSid -AccountName ([string]$Service.StartName) -ServiceName $Name
    $imagePath = Resolve-ServiceExecutablePath -CommandLine ([string]$Service.PathName)
    $image = Get-VerifiedMicrosoftServiceComponent -Path $imagePath -ExpectedExtension '.exe'

    $serviceDll = $null
    $parametersPath = Join-Path $registryPath 'Parameters'
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $parametersPath -PathType Container -ErrorAction Stop) {
        $parameters = Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $parametersPath -ErrorAction Stop
        $serviceDllProperty = $parameters.PSObject.Properties['ServiceDll']
        if ($null -ne $serviceDllProperty) {
            if ($serviceDllProperty.Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$serviceDllProperty.Value)) {
                throw 'The service ServiceDll value is not one unambiguous path.'
            }
            $serviceDll = Get-VerifiedMicrosoftServiceComponent -Path ([string]$serviceDllProperty.Value) -ExpectedExtension '.dll'
        }
    }

    $systemSvchost = Get-SafeFullPath -Path ([IO.Path]::Combine([Environment]::SystemDirectory, 'svchost.exe'))
    if ($registryType -eq [uint32]0x20 -and $image.Path -ine $systemSvchost) {
        throw 'A share-process service is not hosted by the canonical System32 svchost.exe.'
    }
    if ([IO.Path]::GetFileName($image.Path) -ieq 'svchost.exe' -and $null -eq $serviceDll) {
        throw 'An svchost-hosted service has no verifiable Parameters\ServiceDll component.'
    }
    if ([IO.Path]::GetFileName($image.Path) -ine 'svchost.exe' -and $null -ne $serviceDll) {
        throw 'A direct executable service has an unexpected ServiceDll mapping.'
    }

    return [pscustomobject][ordered]@{
        AccountSid   = $accountSid
        RegistryType = [uint32]$registryType
        Image        = $image
        ServiceDll   = $serviceDll
    }
}

function Test-ServiceIdentityFingerprintEquivalent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Left,
        [Parameter(Mandatory = $true)] $Right
    )

    $leftJson = ConvertTo-Json -InputObject $Left.Identity -Compress -Depth 8
    $rightJson = ConvertTo-Json -InputObject $Right.Identity -Compress -Depth 8
    return ($leftJson -ceq $rightJson)
}

function Test-ServiceStableMappingEquivalent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Left,
        [Parameter(Mandatory = $true)] $Right
    )

    return (
        ([string]$Left.BinaryPathName -ceq [string]$Right.BinaryPathName) -and
        ([string]$Left.AccountName -ceq [string]$Right.AccountName) -and
        ([string]$Left.ServiceType -ceq [string]$Right.ServiceType) -and
        ([string]$Left.Identity.AccountSid -ceq [string]$Right.Identity.AccountSid) -and
        ([uint32]$Left.Identity.RegistryType -eq [uint32]$Right.Identity.RegistryType) -and
        ([string]$Left.Identity.Image.Path -ieq [string]$Right.Identity.Image.Path) -and
        (($null -eq $Left.Identity.ServiceDll) -eq ($null -eq $Right.Identity.ServiceDll)) -and
        ($null -eq $Left.Identity.ServiceDll -or
         [string]$Left.Identity.ServiceDll.Path -ieq [string]$Right.Identity.ServiceDll.Path)
    )
}

function Format-ServiceIdentityEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)] [string]$Label
    )

    $image = $State.Identity.Image
    $serviceDll = if ($null -ne $State.Identity.ServiceDll) {
        'ServiceDll={0}; SHA256={1}; signer={2}; thumbprint={3}' -f
            $State.Identity.ServiceDll.Path, $State.Identity.ServiceDll.Sha256,
            $State.Identity.ServiceDll.SignerSubject, $State.Identity.ServiceDll.SignerThumbprint
    }
    else { 'ServiceDll=none' }
    return '{0}: account={1} [{2}]; type=0x{3:x}; image={4}; SHA256={5}; signer={6}; thumbprint={7}; {8}' -f
        $Label, $State.AccountName, $State.Identity.AccountSid, [uint32]$State.Identity.RegistryType,
        $image.Path, $image.Sha256, $image.SignerSubject, $image.SignerThumbprint, $serviceDll
}

function Get-ServiceBeforeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Name
    )

    $escapedName = $Name.Replace("'", "''")
    $service = CimCmdlets\Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $escapedName) -ErrorAction Stop
    if ($null -eq $service) {
        throw ("Service '{0}' is not installed." -f $Name)
    }
    $identity = Get-ServiceIdentityEvidence -Service $service -Name $Name

    return [pscustomobject][ordered]@{
        Name             = [string]$service.Name
        DisplayName      = [string]$service.DisplayName
        BinaryPathName   = [string]$service.PathName
        AccountName      = [string]$service.StartName
        ServiceType      = [string]$service.ServiceType
        Identity         = $identity
        StartMode        = [string]$service.StartMode
        DelayedAutoStart = [bool]$service.DelayedAutoStart
        State            = [string]$service.State
        Started          = [bool]$service.Started
    }
}

function Set-ServiceStartConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [ValidateSet('Auto', 'Manual', 'Disabled')] [string]$StartMode,
        [bool]$DelayedAutoStart = $false
    )

    $scStart = switch ($StartMode) {
        'Auto'     { if ($DelayedAutoStart) { 'delayed-auto' } else { 'auto' } }
        'Manual'   { 'demand' }
        'Disabled' { 'disabled' }
    }

    $scPath = Get-TrustedSystemExecutable -Name 'sc.exe'
    $output = @(& $scPath config $Name start= $scStart 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ("sc.exe failed to set service '{0}' to '{1}': {2}" -f $Name, $scStart, ($output -join ' '))
    }
}

function Restore-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $BeforeState
    )

    Set-ServiceStartConfiguration -Name ([string]$BeforeState.Name) -StartMode ([string]$BeforeState.StartMode) -DelayedAutoStart ([bool]$BeforeState.DelayedAutoStart)
    $service = Microsoft.PowerShell.Management\Get-Service -Name ([string]$BeforeState.Name) -ErrorAction Stop

    if ([bool]$BeforeState.Started -and $service.Status -ne 'Running') {
        Microsoft.PowerShell.Management\Start-Service -Name $service.Name -Confirm:$false -ErrorAction Stop
    }
    elseif (-not [bool]$BeforeState.Started -and $service.Status -eq 'Running') {
        Microsoft.PowerShell.Management\Stop-Service -Name $service.Name -Confirm:$false -ErrorAction Stop
    }

    $observed = Get-ServiceBeforeState -Name ([string]$BeforeState.Name)
    if (-not (Test-RestoreStateEquivalent -Kind 'Service' -Left $observed -Right $BeforeState)) {
        throw ("Service '{0}' post-restore verification failed." -f $BeforeState.Name)
    }
}

function ConvertFrom-NativeFinalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    $normalized = $Path
    if ($normalized.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        $normalized = '\\' + $normalized.Substring(8)
    }
    elseif ($normalized.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(4)
    }
    return (Get-SafeFullPath -Path $normalized)
}

function Open-DirectoryGuard {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    return $script:NativeMethods.OpenDirectoryGuard($Path)
}

function Open-DirectoryGuardChain {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    Initialize-NativeMethods
    $fullPath = Get-SafeFullPath -Path $Path
    $rootPath = [IO.Path]::GetPathRoot($fullPath)
    $directoryPaths = New-Object System.Collections.ArrayList
    $currentPath = $fullPath
    while ($true) {
        $directoryPaths.Insert(0, $currentPath)
        if ($currentPath -ieq $rootPath) { break }
        $parent = [IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) {
            throw ("Could not resolve the complete directory chain for '{0}'." -f $fullPath)
        }
        $currentPath = Get-SafeFullPath -Path $parent.FullName
    }

    $guards = New-Object System.Collections.ArrayList
    try {
        foreach ($directoryPath in $directoryPaths) {
            $guard = Open-DirectoryGuard -Path $directoryPath
            $resolvedPath = ConvertFrom-NativeFinalPath -Path $guard.FinalPath
            if ($resolvedPath -ine (Get-SafeFullPath -Path $directoryPath)) {
                $guard.Dispose()
                throw ("Directory identity changed while securing '{0}'." -f $fullPath)
            }
            [void]$guards.Add($guard)
        }
        return @($guards)
    }
    catch {
        foreach ($guard in @($guards)) {
            if ($null -ne $guard) { $guard.Dispose() }
        }
        throw
    }
}

function Remove-OldRegularTempFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Root,
        [Parameter(Mandatory = $true)] [datetime]$CutoffUtc
    )

    return $script:NativeMethods.DeleteOldRegularFile($Path, $Root, $CutoffUtc.ToFileTimeUtc())
}

function Get-DriveTypeForPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Path)

    $driveRoot = [IO.Path]::GetPathRoot((Get-SafeFullPath -Path $Path))
    $drive = New-Object -TypeName IO.DriveInfo -ArgumentList $driveRoot
    return $drive.DriveType
}

function Invoke-SafeTempTraversal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$CurrentDirectory,
        [Parameter(Mandatory = $true)] [string]$Root,
        [Parameter(Mandatory = $true)] [datetime]$CutoffUtc,
        [Parameter(Mandatory = $true)] [hashtable]$Metrics,
        [Parameter(Mandatory = $true)] [int]$Depth,
        [switch]$IsRoot
    )

    if ($Depth -gt 256) {
        $Metrics.FailedItems++
        return
    }

    $guard = $null
    try {
        $expectedPath = Get-SafeFullPath -Path $CurrentDirectory
        $guard = Open-DirectoryGuard -Path $expectedPath
        $finalPath = ConvertFrom-NativeFinalPath -Path $guard.FinalPath
        if ($finalPath -ine $expectedPath -or -not (Test-PathIsWithin -Path $finalPath -Root $Root -AllowEqual)) {
            throw 'Directory identity changed or resolved outside the approved temporary root.'
        }

        try {
            $children = @(Get-ChildItem -LiteralPath $expectedPath -Force -ErrorAction Stop)
        }
        catch {
            if ($IsRoot) {
                throw 'The root temporary folder could not be enumerated; no cleanup result was claimed.'
            }
            $Metrics.FailedItems++
            return
        }

        foreach ($item in $children) {
            $Metrics.ProcessedItems++
            if (($Metrics.ProcessedItems % 100) -eq 0) {
                Write-Progress -Id 2 -Activity 'Cleaning temporary folder' -Status ("Processed {0:N0} items; removed {1:N0} files" -f $Metrics.ProcessedItems, $Metrics.DeletedFiles) -PercentComplete -1
            }

            try {
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $Metrics.SkippedReparsePoints++
                    continue
                }

                if ($item.PSIsContainer) {
                    $Metrics.PreservedDirectories++
                    Invoke-SafeTempTraversal -CurrentDirectory $item.FullName -Root $Root -CutoffUtc $CutoffUtc -Metrics $Metrics -Depth ($Depth + 1)
                    continue
                }

                # The native helper opens the candidate without delete sharing, validates its
                # final path/type/timestamp, and marks that exact handle for deletion.
                $deleteResult = Remove-OldRegularTempFile -Path ([string]$item.FullName) -Root ([string]$Root) -CutoffUtc $CutoffUtc
                switch ([string]$deleteResult.Status) {
                    'Deleted' {
                        $Metrics.DeletedFiles++
                        $Metrics.FreedBytes += [long]$deleteResult.Length
                    }
                    'Recent' { $Metrics.SkippedRecent++ }
                    'ReparsePoint' { $Metrics.SkippedReparsePoints++ }
                    'NotRegularFile' { $Metrics.SkippedReparsePoints++ }
                    default { $Metrics.FailedItems++ }
                }
            }
            catch {
                # File names are intentionally not logged; they may contain sensitive data.
                $Metrics.FailedItems++
            }
        }
    }
    catch {
        if ($IsRoot) {
            throw
        }
        $Metrics.FailedItems++
    }
    finally {
        if ($null -ne $guard) {
            $guard.Dispose()
        }
    }
}

function Remove-EligibleTempContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Target,
        [Parameter(Mandatory = $true)] [datetime]$CutoffUtc
    )

    $targetFull = Get-SafeFullPath -Path $Target
    if (Test-IsUnsafeCleanupRoot -Path $targetFull) {
        throw ("Cleanup target '{0}' is not one of the two exact trusted temporary roots." -f $targetFull)
    }
    if (Test-PathContainsReparsePoint -Path $targetFull) {
        throw ("Cleanup target '{0}' or a parent is a reparse point; traversal was refused." -f $targetFull)
    }

    if ((Get-DriveTypeForPath -Path $targetFull) -ne [IO.DriveType]::Fixed) {
        throw ("Cleanup target '{0}' is not on a local fixed drive." -f $targetFull)
    }

    foreach ($protectedPath in @([string]$PSScriptRoot, [string]$script:LogPath, [string]$script:BackupPath, [string]$script:ReportPath)) {
        if (-not [string]::IsNullOrWhiteSpace($protectedPath) -and
            (Test-PathIsWithin -Path $protectedPath -Root $targetFull -AllowEqual)) {
            throw ("Protected operational path '{0}' is inside the cleanup target." -f $protectedPath)
        }
    }

    Initialize-NativeMethods
    $metrics = @{
        ProcessedItems       = 0L
        DeletedFiles         = 0L
        PreservedDirectories = 0L
        FreedBytes           = 0L
        SkippedRecent        = 0L
        SkippedReparsePoints = 0L
        FailedItems          = 0L
    }

    try {
        Invoke-SafeTempTraversal -CurrentDirectory $targetFull -Root $targetFull -CutoffUtc $CutoffUtc -Metrics $metrics -Depth 0 -IsRoot
    }
    finally {
        Write-Progress -Id 2 -Activity 'Cleaning temporary folder' -Completed
    }

    return [pscustomobject][ordered]@{
        Target                  = $targetFull
        CutoffUtc               = $CutoffUtc.ToString('o')
        ProcessedItems          = $metrics.ProcessedItems
        DeletedFiles            = $metrics.DeletedFiles
        DeletedDirectories      = 0L
        PreservedDirectories    = $metrics.PreservedDirectories
        FreedBytes              = $metrics.FreedBytes
        SkippedRecent           = $metrics.SkippedRecent
        SkippedReparsePoints    = $metrics.SkippedReparsePoints
        FailedItems             = $metrics.FailedItems
    }
}

function Invoke-TempFolderOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation
    )

    $cutoff = [DateTime]::UtcNow.AddDays(-1 * $MinimumAgeDays)
    $context = "Folder={0}; cutoff UTC={1}" -f $Operation.Target, $cutoff.ToString('o')
    if (-not (Request-OperationConsent -Operation $Operation -AdditionalContext $context)) {
        Write-Log -Level 'INFO' -Message ("Skipped {0} by consent policy." -f $Operation.Id)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }

    if (-not (Test-ShouldProcessOperation -Target $Operation.Target -Action ("Delete eligible contents older than {0} day(s)" -f $MinimumAgeDays))) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'No content was deleted.')
    }
    $maintenanceBlock = Get-MaintenanceBlockMessage
    if ($null -ne $maintenanceBlock) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $maintenanceBlock)
    }

    $before = [pscustomobject]@{ Target = $Operation.Target; CutoffUtc = $cutoff.ToString('o'); Reversible = $false }
    $record = New-ChangeRecord -Operation $Operation -BeforeState $before -RestoreKind 'None'
    try {
        $metrics = Remove-EligibleTempContent -Target $Operation.Target -CutoffUtc $cutoff
        $message = "Removed {0:N0} files; preserved all folders; freed approximately {1}; {2:N0} items could not be removed." -f $metrics.DeletedFiles, (Format-ByteSize -Bytes $metrics.FreedBytes), $metrics.FailedItems
        if ($metrics.FailedItems -gt 0) {
            Complete-ChangeRecord -Record $record -Status 'Partial' -AfterState $metrics -Message $message
            Set-PartialExitCode
            Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Partial' -Message $message)
        }
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $metrics -Message $message
        if ($metrics.DeletedFiles -eq 0) {
            Write-Log -Level 'INFO' -Message ("{0}: {1}" -f $Operation.Id, $message)
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'NoChange' -Message $message)
        }
        Write-Log -Level 'SUCCESS' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        Complete-ChangeRecord -Record $record -Status 'Failed' -AfterState $null -Message $_.Exception.Message
        throw
    }
}

function Invoke-ServiceOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation
    )

    if ($script:CriticalServiceDenylist -icontains $Operation.ServiceName) {
        throw ("Critical service '{0}' is blocked by policy." -f $Operation.ServiceName)
    }

    $before = Get-ServiceBeforeState -Name $Operation.ServiceName
    try {
        Assert-RestoreStateSafe -Kind 'Service' -State $before -Operation $Operation -Label 'BeforeState'
    }
    catch {
        $message = 'Service identity/startup state cannot be captured safely for rollback; it was not changed.'
        Write-Log -Level 'WARN' -Message ("{0}: {1} {2}" -f $Operation.Id, $message, $_.Exception.Message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (@('Auto', 'Manual', 'Disabled') -notcontains $before.StartMode -or
        (($before.State -eq 'Running') -ne [bool]$before.Started)) {
        $message = 'Service startup/runtime state cannot be represented safely by the rollback model; it was not changed.'
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (@('Running', 'Stopped') -notcontains $before.State) {
        $message = ("Service is in transient/unsupported state '{0}' and was not changed." -f $before.State)
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if ($before.StartMode -eq 'Disabled' -and $before.State -eq 'Running') {
        $message = 'Service is Disabled but Running; that unusual state cannot be restored exactly and was not changed.'
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if ($before.StartMode -eq 'Manual' -and -not $before.Started -and -not $DisableDemandStartServices) {
        $message = 'Service is Manual and Stopped, so it has no active CPU cost. Use -DisableDemandStartServices only if preventing future on-demand use is intentional.'
        Write-Log -Level 'INFO' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message $message)
    }
    if ($before.StartMode -eq 'Disabled' -and -not $before.Started) {
        $message = 'Service is already Disabled and Stopped.'
        Write-Log -Level 'INFO' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message $message)
    }

    $dependents = @(Microsoft.PowerShell.Management\Get-Service -Name $Operation.ServiceName -DependentServices -ErrorAction Stop)
    $identityContext = Format-ServiceIdentityEvidence -State $before -Label 'verified current identity'
    $context = "Startup={0}; State={1}; installed dependents={2}. {3}" -f
        $before.StartMode, $before.State, $dependents.Count, $identityContext
    if (-not (Request-OperationConsent -Operation $Operation -AdditionalContext $context)) {
        Write-Log -Level 'INFO' -Message ("Skipped {0} by consent policy." -f $Operation.Id)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }

    if ($dependents.Count -gt 0) {
        $message = "Service has {0} installed dependent service(s); it was not changed because disabling it could prevent those services from starting." -f $dependents.Count
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }

    if (-not (Test-ShouldProcessOperation -Target $Operation.ServiceName -Action 'Stop and set startup mode to Disabled')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Service was not changed.')
    }

    Ensure-BestEffortRestorePoint
    $freshBefore = Get-ServiceBeforeState -Name $Operation.ServiceName
    $freshDependents = @(Microsoft.PowerShell.Management\Get-Service -Name $Operation.ServiceName -DependentServices -ErrorAction Stop)
    $freshDependentNames = @($freshDependents | ForEach-Object { $_.Name } | Sort-Object) -join '|'
    $priorDependentNames = @($dependents | ForEach-Object { $_.Name } | Sort-Object) -join '|'
    if (-not (Test-RestoreStateEquivalent -Kind 'Service' -Left $freshBefore -Right $before) -or
        -not (Test-ServiceIdentityFingerprintEquivalent -Left $freshBefore -Right $before) -or
        $freshDependents.Count -ne $dependents.Count -or
        $freshDependentNames -cne $priorDependentNames) {
        $message = 'Service or dependency state changed after consent; it was not modified. Review the new state and run again.'
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (@('Auto', 'Manual', 'Disabled') -notcontains $freshBefore.StartMode -or
        @('Running', 'Stopped') -notcontains $freshBefore.State -or
        (($freshBefore.State -eq 'Running') -ne [bool]$freshBefore.Started) -or
        $freshDependents.Count -gt 0) {
        $message = 'Service is no longer in a safely representable, dependency-free state; it was not modified.'
        Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $Operation.Id, $message)
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    $before = $freshBefore
    $record = New-ChangeRecord -Operation $Operation -BeforeState $before -RestoreKind 'Service'
    try {
        Set-ServiceStartConfiguration -Name $Operation.ServiceName -StartMode 'Disabled'
        $service = Microsoft.PowerShell.Management\Get-Service -Name $Operation.ServiceName -ErrorAction Stop
        if ($service.Status -ne 'Stopped') {
            Microsoft.PowerShell.Management\Stop-Service -Name $Operation.ServiceName -Confirm:$false -ErrorAction Stop
        }

        $after = Get-ServiceBeforeState -Name $Operation.ServiceName
        if ($after.StartMode -ne 'Disabled' -or $after.Started -or $after.State -ne 'Stopped' -or
            [bool]$after.DelayedAutoStart -or
            -not (Test-ServiceStableMappingEquivalent -Left $after -Right $before) -or
            -not (Test-ServiceIdentityFingerprintEquivalent -Left $after -Right $before)) {
            throw 'Post-change verification failed.'
        }

        $message = "Service '{0}' is Disabled and Stopped." -f $Operation.ServiceName
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $after -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        $primaryError = $_.Exception.Message
        $failureMessage = Complete-ReversibleFailure -Record $record -PrimaryError $primaryError `
            -Kind 'Service' -BeforeState $before `
            -RollbackAction { Restore-ServiceState -BeforeState $before } `
            -ReadCurrentState { Get-ServiceBeforeState -Name $Operation.ServiceName }
        throw $failureMessage
    }
}

function Invoke-DeliveryOptimizationOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    if (-not (Request-OperationConsent -Operation $Operation)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }
    if (-not (Test-ShouldProcessOperation -Target 'Delivery Optimization cache' -Action 'Delete unpinned cached content')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Cache was not changed.')
    }
    $maintenanceBlock = Get-MaintenanceBlockMessage
    if ($null -ne $maintenanceBlock) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $maintenanceBlock)
    }

    $record = New-ChangeRecord -Operation $Operation -BeforeState ([pscustomobject]@{ Reversible = $false }) -RestoreKind 'None'
    try {
        DeliveryOptimization\Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
        $message = 'Delivery Optimization unpinned cache was cleared.'
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $null -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        Complete-ChangeRecord -Record $record -Status 'Failed' -AfterState $null -Message $_.Exception.Message
        throw
    }
}

function Invoke-Dism {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string[]]$Arguments
    )

    $dismPath = Get-TrustedSystemExecutable -Name 'Dism.exe'
    $output = New-Object System.Collections.ArrayList
    $script:DeferredLogFailure = $null
    & $dismPath @Arguments 2>&1 | ForEach-Object {
        $line = $_
        [void]$output.Add([string]$line)
        $text = [string]$line
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            Write-Log -Level 'DEBUG' -Message ("DISM: {0}" -f $text) -NoConsole -DeferFailure
            $progressMatch = [regex]::Match($text, '(?<Percent>\d{1,3}(?:\.\d+)?)%')
            if ($progressMatch.Success) {
                $progressValue = [math]::Min(100, [math]::Max(0, [double]$progressMatch.Groups['Percent'].Value))
                Write-Progress -Id 2 -Activity 'DISM component-store maintenance' -Status $text.Trim() -PercentComplete ([int]$progressValue)
            }
        }
    }
    $exitCode = $LASTEXITCODE
    Write-Progress -Id 2 -Activity 'DISM component-store maintenance' -Completed
    if (@(0, 3010) -notcontains $exitCode) {
        $loggingNote = if ($null -ne $script:DeferredLogFailure) { ' Streaming log output was also incomplete.' } else { '' }
        throw ("DISM failed with exit code {0}. See log: {1}.{2}" -f $exitCode, $script:LogPath, $loggingNote)
    }
    if ($RequireReliableLogging -and $null -ne $script:DeferredLogFailure) {
        throw 'DISM completed, but streaming output could not be recorded completely while -RequireReliableLogging was active. Inspect Windows servicing state before retrying.'
    }
    return [pscustomobject][ordered]@{
        ExitCode        = [int]$exitCode
        RestartRequired = ($exitCode -eq 3010)
        Output          = @($output)
    }
}

function Invoke-ComponentStoreOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    if (-not (Request-OperationConsent -Operation $Operation)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }
    if (-not (Test-ShouldProcessOperation -Target 'Windows component store' -Action 'Analyze and run DISM StartComponentCleanup')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Component store was not changed.')
    }
    $maintenanceBlock = Get-MaintenanceBlockMessage
    if ($null -ne $maintenanceBlock) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $maintenanceBlock)
    }
    $powerBlock = Get-LongMaintenancePowerBlockMessage
    if ($null -ne $powerBlock) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $powerBlock)
    }

    $record = New-ChangeRecord -Operation $Operation -BeforeState ([pscustomobject]@{ Reversible = $false; ResetBaseUsed = $false }) -RestoreKind 'None'
    try {
        Write-Log -Level 'INFO' -Message 'Analyzing the Windows component store. This can take several minutes.'
        $analysisResult = Invoke-Dism -Arguments @('/Online', '/Cleanup-Image', '/AnalyzeComponentStore')
        if ($analysisResult.RestartRequired) {
            $message = 'DISM analysis reported that a restart is required. StartComponentCleanup was not started; restart Windows and run the operation again.'
            Complete-ChangeRecord -Record $record -Status 'Failed' -AfterState ([pscustomobject]@{
                AnalysisExitCode = [int]$analysisResult.ExitCode
                CleanupStarted = $false
                ResetBaseUsed = $false
                RestartRequired = $true
            }) -Message $message
            Write-Log -Level 'WARN' -Message $message
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message -RestartRequired $true)
        }
        $powerBlock = Get-LongMaintenancePowerBlockMessage
        if ($null -ne $powerBlock) { throw $powerBlock }
        Write-Log -Level 'INFO' -Message 'Running DISM StartComponentCleanup. ResetBase is not used.'
        $cleanupResult = Invoke-Dism -Arguments @('/Online', '/Cleanup-Image', '/StartComponentCleanup')
        $restartRequired = [bool]($analysisResult.RestartRequired -or $cleanupResult.RestartRequired)
        $restartNote = if ($restartRequired) { ' Windows reported that a restart is required; the script did not restart the computer.' } else { '' }
        $message = 'DISM component-store cleanup completed successfully; ResetBase was not used.{0}' -f $restartNote
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState ([pscustomobject]@{
            ExitCode = [int]$cleanupResult.ExitCode
            ResetBaseUsed = $false
            RestartRequired = $restartRequired
        }) -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message -RestartRequired $restartRequired)
    }
    catch {
        Complete-ChangeRecord -Record $record -Status 'Failed' -AfterState $null -Message $_.Exception.Message
        throw
    }
}

function Get-OptimizableVolumes {
    [CmdletBinding()]
    param()

    if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'Storage\Get-Volume' -ErrorAction SilentlyContinue)) {
        return @()
    }

    return @(Storage\Get-Volume -ErrorAction Stop | Where-Object {
        $null -ne $_.DriveLetter -and
        -not [string]::IsNullOrWhiteSpace([string]$_.ObjectId) -and
        -not [string]::IsNullOrWhiteSpace([string]$_.UniqueId) -and
        $_.DriveType -eq 'Fixed' -and
        $_.HealthStatus -eq 'Healthy' -and
        @('NTFS', 'ReFS') -icontains ([string]$_.FileSystem)
    } | Sort-Object DriveLetter)
}

function Invoke-OptimizeVolumesOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    $volumes = @(Get-OptimizableVolumes)
    if ($volumes.Count -eq 0) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Unavailable' -Message 'No healthy fixed NTFS/ReFS volumes were found.')
    }
    if ($null -ne $VolumeDriveLetter -and @($VolumeDriveLetter).Count -gt 0) {
        $requestedLetters = @($VolumeDriveLetter | ForEach-Object { $_.TrimEnd(':').ToUpperInvariant() } | Select-Object -Unique)
        $availableLetters = @($volumes | ForEach-Object { ([string]$_.DriveLetter).ToUpperInvariant() })
        if (@($requestedLetters | Where-Object { $availableLetters -notcontains $_ }).Count -gt 0) {
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message 'At least one requested drive is not a healthy fixed NTFS/ReFS volume.')
        }
        $volumes = @($volumes | Where-Object { $requestedLetters -contains ([string]$_.DriveLetter).ToUpperInvariant() })
    }
    $consentedVolumes = New-Object System.Collections.ArrayList
    foreach ($volume in $volumes) {
        $volumeOperation = New-Operation -Id $Operation.Id -Category $Operation.Category `
            -DisplayName ("Optimize volume {0}:" -f $volume.DriveLetter) -Description $Operation.Description `
            -Impact $Operation.Impact -Risk $Operation.Risk -Recommended $Operation.Recommended `
            -Reversible $Operation.Reversible -Kind $Operation.Kind
        $context = "Drive={0}:; file system={1}; size={2}; free={3}" -f $volume.DriveLetter, $volume.FileSystem, `
            (Format-ByteSize -Bytes ([long]$volume.Size)), (Format-ByteSize -Bytes ([long]$volume.SizeRemaining))
        if (-not (Request-OperationConsent -Operation $volumeOperation -AdditionalContext $context)) {
            continue
        }
        [void]$consentedVolumes.Add($volume)
    }
    if ($consentedVolumes.Count -eq 0) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'No volume was approved.')
    }
    if (-not $script:IsWhatIf -and -not $AcknowledgeStorageIo) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message 'Volume optimization requires -AcknowledgeStorageIo because it can create sustained storage I/O.')
    }

    $approvedVolumes = New-Object System.Collections.ArrayList
    $whatIfCount = 0
    foreach ($volume in @($consentedVolumes)) {
        if (-not (Test-ShouldProcessOperation -Target ("{0}:" -f $volume.DriveLetter) -Action 'Run media-aware default Optimize-Volume operation')) {
            $whatIfCount++
            continue
        }
        [void]$approvedVolumes.Add($volume)
    }
    if ($approvedVolumes.Count -eq 0) {
        if ($whatIfCount -gt 0) {
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Volumes were not optimized.')
        }
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'No volume was selected by ShouldProcess.')
    }
    $volumes = @($approvedVolumes)
    $powerBlock = Get-LongMaintenancePowerBlockMessage
    if ($null -ne $powerBlock) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $powerBlock)
    }

    $before = @($volumes | ForEach-Object {
        [pscustomobject]@{
            ObjectId = [string]$_.ObjectId
            UniqueId = [string]$_.UniqueId
            DriveLetter = [string]$_.DriveLetter
            FileSystem = [string]$_.FileSystem
            Size = [long]$_.Size
            SizeRemaining = [long]$_.SizeRemaining
        }
    })
    $record = New-ChangeRecord -Operation $Operation -BeforeState $before -RestoreKind 'None'
    $completed = New-Object System.Collections.ArrayList
    try {
        for ($index = 0; $index -lt $volumes.Count; $index++) {
            $volume = $volumes[$index]
            $maintenanceBlock = Get-MaintenanceBlockMessage
            if ($null -ne $maintenanceBlock) {
                throw $maintenanceBlock
            }
            $powerBlock = Get-LongMaintenancePowerBlockMessage
            if ($null -ne $powerBlock) {
                throw $powerBlock
            }
            $freshVolume = @(Storage\Get-Volume -ObjectId ([string]$volume.ObjectId) -ErrorAction Stop)
            if ($freshVolume.Count -ne 1 -or
                [string]$freshVolume[0].ObjectId -cne [string]$volume.ObjectId -or
                [string]$freshVolume[0].UniqueId -cne [string]$volume.UniqueId -or
                [long]$freshVolume[0].Size -ne [long]$volume.Size -or
                [string]$freshVolume[0].DriveLetter -ine [string]$volume.DriveLetter -or
                [string]$freshVolume[0].DriveType -ne 'Fixed' -or
                [string]$freshVolume[0].HealthStatus -ne 'Healthy' -or
                @('NTFS', 'ReFS') -inotcontains ([string]$freshVolume[0].FileSystem)) {
                throw ("Volume identity or eligibility changed after approval for drive {0}:; optimization was refused." -f $volume.DriveLetter)
            }
            $percent = [int](($index / [math]::Max(1, $volumes.Count)) * 100)
            Write-Progress -Id 2 -Activity 'Optimizing fixed volumes' -Status ("Optimizing {0}:" -f $volume.DriveLetter) -PercentComplete $percent
            Write-Log -Level 'INFO' -Message ("Running media-aware Optimize-Volume on {0}:" -f $volume.DriveLetter)
            $script:DeferredLogFailure = $null
            Storage\Optimize-Volume -ObjectId ([string]$volume.ObjectId) -Verbose -Confirm:$false -ErrorAction Stop 4>&1 | ForEach-Object {
                $line = $_
                Write-Log -Level 'DEBUG' -Message ("Optimize-Volume {0}: {1}" -f $volume.DriveLetter, [string]$line) -NoConsole -DeferFailure
            }
            [void]$completed.Add([string]$volume.DriveLetter)
            if ($RequireReliableLogging -and $null -ne $script:DeferredLogFailure) {
                throw ("Volume {0}: completed its Windows optimization call, but streaming output was not logged completely. Inspect the volume before retrying." -f $volume.DriveLetter)
            }
        }
        Write-Progress -Id 2 -Activity 'Optimizing fixed volumes' -Completed
        $message = "Optimized {0:N0} fixed volume(s) using Windows media-aware defaults." -f $completed.Count
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState @($completed) -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        Write-Progress -Id 2 -Activity 'Optimizing fixed volumes' -Completed
        Complete-ChangeRecord -Record $record -Status 'Failed' -AfterState @($completed) -Message $_.Exception.Message
        throw
    }
}

function Get-TcpAutoTuningState {
    [CmdletBinding()]
    param()

    return @(NetTCPIP\Get-NetTCPSetting -ErrorAction Stop | ForEach-Object {
        [pscustomobject][ordered]@{
            SettingName                = [string]$_.SettingName
            AutoTuningLevelLocal       = [string]$_.AutoTuningLevelLocal
            AutoTuningLevelGroupPolicy = [string]$_.AutoTuningLevelGroupPolicy
            AutoTuningLevelEffective   = [string]$_.AutoTuningLevelEffective
        }
    })
}

function Restore-TcpAutoTuningState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $BeforeState)

    foreach ($setting in @($BeforeState)) {
        if ([string]$setting.AutoTuningLevelEffective -eq 'GroupPolicy') {
            continue
        }
        NetTCPIP\Set-NetTCPSetting -SettingName ([string]$setting.SettingName) -AutoTuningLevelLocal ([string]$setting.AutoTuningLevelLocal) -Confirm:$false -ErrorAction Stop
    }

    $names = @($BeforeState | ForEach-Object { [string]$_.SettingName })
    $observed = @(Get-TcpAutoTuningState | Where-Object { $names -icontains $_.SettingName })
    if (-not (Test-RestoreStateEquivalent -Kind 'TcpAutoTuning' -Left $observed -Right $BeforeState)) {
        throw 'TCP auto-tuning post-restore verification failed.'
    }
}

function Invoke-TcpAutoTuningOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    $allSettings = @(Get-TcpAutoTuningState)
    $policyManaged = @($allSettings | Where-Object { $_.AutoTuningLevelEffective -eq 'GroupPolicy' })
    $mutableTemplates = @('InternetCustom', 'DatacenterCustom')
    $concreteLevels = @('Disabled', 'HighlyRestricted', 'Restricted', 'Normal', 'Experimental')
    $targets = @($allSettings | Where-Object {
        $mutableTemplates -contains $_.SettingName -and
        $concreteLevels -contains $_.AutoTuningLevelLocal -and
        $_.AutoTuningLevelEffective -eq 'Local' -and
        $_.AutoTuningLevelGroupPolicy -eq 'NotConfigured' -and
        $_.AutoTuningLevelLocal -ne 'Normal'
    })

    if ($targets.Count -eq 0) {
        $message = if ($policyManaged.Count -gt 0) {
            "No local change is needed; {0} template(s) are policy-managed and were left unchanged." -f $policyManaged.Count
        }
        else {
            'No eligible non-policy custom TCP template requires normalization.'
        }
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message $message)
    }

    $summary = ($targets | ForEach-Object { '{0}={1}' -f $_.SettingName, $_.AutoTuningLevelLocal }) -join '; '
    if (-not (Request-OperationConsent -Operation $Operation -AdditionalContext $summary)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }
    if (-not $script:IsWhatIf -and (Test-IsRemoteSession) -and -not $AllowNetworkChangeInRemoteSession) {
        $message = 'TCP template changes are blocked in a remote session. Run locally or explicitly use -AllowNetworkChangeInRemoteSession.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (-not $script:IsWhatIf -and -not $AcknowledgeNetworkInterruption) {
        $message = 'TCP template changes require -AcknowledgeNetworkInterruption because active connectivity may be affected.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (-not (Test-ShouldProcessOperation -Target ($targets.SettingName -join ', ') -Action 'Set TCP AutoTuningLevelLocal to Normal')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'TCP settings were not changed.')
    }

    Ensure-BestEffortRestorePoint
    $approvedTargetNames = @($targets | ForEach-Object { [string]$_.SettingName })
    $freshTargets = @(Get-TcpAutoTuningState | Where-Object { $approvedTargetNames -icontains $_.SettingName })
    if ($freshTargets.Count -ne $targets.Count -or
        -not (Test-RestoreStateEquivalent -Kind 'TcpAutoTuning' -Left $freshTargets -Right $targets)) {
        $message = 'TCP template state changed after consent; no TCP setting was modified. Review the new state and run again.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    $targets = $freshTargets
    $record = New-ChangeRecord -Operation $Operation -BeforeState $targets -RestoreKind 'TcpAutoTuning'
    try {
        foreach ($setting in $targets) {
            NetTCPIP\Set-NetTCPSetting -SettingName $setting.SettingName -AutoTuningLevelLocal Normal -Confirm:$false -ErrorAction Stop
        }
        $targetNames = @($targets | ForEach-Object { [string]$_.SettingName })
        $after = @(Get-TcpAutoTuningState | Where-Object { $targetNames -icontains $_.SettingName })
        $afterNames = @($after | ForEach-Object { [string]$_.SettingName } | Select-Object -Unique)
        if ($after.Count -ne $targets.Count -or $afterNames.Count -ne $targetNames.Count -or
            @($after | Where-Object {
                $_.AutoTuningLevelLocal -ne 'Normal' -or
                $_.AutoTuningLevelEffective -ne 'Local' -or
                $_.AutoTuningLevelGroupPolicy -ne 'NotConfigured'
            }).Count -gt 0) {
            throw 'Post-change TCP auto-tuning verification failed.'
        }
        $message = "Normalized {0:N0} TCP template(s); policy-managed templates were not changed." -f $targets.Count
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $after -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        $primaryError = $_.Exception.Message
        $targetNames = @($targets | ForEach-Object { [string]$_.SettingName })
        $failureMessage = Complete-ReversibleFailure -Record $record -PrimaryError $primaryError `
            -Kind 'TcpAutoTuning' -BeforeState $targets `
            -RollbackAction { Restore-TcpAutoTuningState -BeforeState $targets } `
            -ReadCurrentState { @(Get-TcpAutoTuningState | Where-Object { $targetNames -icontains $_.SettingName }) }
        throw $failureMessage
    }
}

function Restore-RssState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $BeforeState)

    $resolvedAdapters = New-Object System.Collections.ArrayList
    foreach ($adapter in @($BeforeState)) {
        $adapterGuid = [guid]([string]$adapter.InterfaceGuid)
        $safeCandidate = @(Get-RssCandidateAdapters | Where-Object {
            $_.InterfaceGuid -ieq $adapterGuid.ToString()
        })
        if ($safeCandidate.Count -ne 1) {
            throw ("Network adapter '{0}' ({1}) is no longer an exact safe wired RSS candidate." -f $adapter.Name, $adapterGuid)
        }
        $present = @(NetAdapter\Get-NetAdapter -ErrorAction Stop | Where-Object {
            $_.HardwareInterface -eq $true -and ([guid]$_.InterfaceGuid) -eq $adapterGuid
        })
        if ($present.Count -ne 1) {
            throw ("The exact physical network adapter '{0}' ({1}) is no longer present." -f $adapter.Name, $adapterGuid)
        }
        [void]$resolvedAdapters.Add([pscustomobject]@{ Saved = $adapter; Current = $present[0] })
    }

    foreach ($resolved in $resolvedAdapters) {
        if ([bool]$resolved.Saved.Enabled) {
            $resolved.Current | NetAdapter\Enable-NetAdapterRss -Confirm:$false -ErrorAction Stop
        }
        else {
            $resolved.Current | NetAdapter\Disable-NetAdapterRss -Confirm:$false -ErrorAction Stop
        }
    }

    $beforeGuids = @($BeforeState | ForEach-Object { [string]$_.InterfaceGuid })
    $verified = $false
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $observed = @(Get-RssCandidateAdapters | Where-Object { $beforeGuids -icontains $_.InterfaceGuid })
        if (Test-RestoreStateEquivalent -Kind 'Rss' -Left $observed -Right $BeforeState) {
            $verified = $true
            break
        }
        Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 500
    }
    if (-not $verified) {
        throw 'RSS post-restore verification failed.'
    }
}

function Invoke-RssOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    $allCandidates = @(Get-RssCandidateAdapters)
    if ($null -ne $AdapterInterfaceGuid -and @($AdapterInterfaceGuid).Count -gt 0) {
        $requestedGuids = @($AdapterInterfaceGuid | ForEach-Object { $_.ToString() })
        $matchedGuids = @($allCandidates | Where-Object { $requestedGuids -icontains $_.InterfaceGuid } | ForEach-Object { $_.InterfaceGuid })
        if (@($requestedGuids | Where-Object { $matchedGuids -inotcontains $_ }).Count -gt 0) {
            $message = 'At least one requested adapter GUID is not an available physical wired RSS candidate.'
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
        }
        $allCandidates = @($allCandidates | Where-Object { $requestedGuids -icontains $_.InterfaceGuid })
    }
    $targets = @($allCandidates | Where-Object { -not $_.Enabled })
    if ($targets.Count -eq 0) {
        if ($null -ne $script:LastRssCandidateDiagnostics -and
            @($script:LastRssCandidateDiagnostics.QueryFailures).Count -gt 0) {
            $message = 'RSS state could not be verified for every physical adapter, so no all-compliant conclusion or mutation was made.'
            Write-Log -Level 'WARN' -Message $message
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
        }
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message 'All supported wired physical adapters already have RSS enabled.')
    }
    $consentedTargets = New-Object System.Collections.ArrayList
    foreach ($target in $targets) {
        $adapterOperation = New-Operation -Id $Operation.Id -Category $Operation.Category `
            -DisplayName ("Enable RSS on {0}" -f $target.Name) -Description $Operation.Description `
            -Impact $Operation.Impact -Risk $Operation.Risk -Recommended $Operation.Recommended `
            -Reversible $Operation.Reversible -Kind $Operation.Kind
        $routeRole = if ($null -eq $target.IsDefaultRoute) { 'default-route role unknown' } elseif ($target.IsDefaultRoute) { 'default-route adapter' } else { 'not currently a default-route adapter' }
        $context = "Name={0}; GUID={1}; description={2}; role={3}" -f $target.Name, $target.InterfaceGuid, $target.InterfaceDescription, $routeRole
        if (-not (Request-OperationConsent -Operation $adapterOperation -AdditionalContext $context)) {
            continue
        }
        [void]$consentedTargets.Add($target)
    }
    if ($consentedTargets.Count -eq 0) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'No adapter was approved.')
    }
    if (-not $script:IsWhatIf -and (Test-IsRemoteSession) -and -not $AllowNetworkChangeInRemoteSession) {
        $message = 'RSS changes are blocked in a remote session. Run locally or explicitly use -AllowNetworkChangeInRemoteSession.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    if (-not $script:IsWhatIf -and -not $AcknowledgeNetworkInterruption) {
        $message = 'RSS changes require -AcknowledgeNetworkInterruption because an adapter can restart and disconnect management traffic.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }

    $approvedTargets = New-Object System.Collections.ArrayList
    $whatIfCount = 0
    foreach ($target in @($consentedTargets)) {
        if (-not (Test-ShouldProcessOperation -Target ("{0} [{1}]" -f $target.Name, $target.InterfaceGuid) -Action 'Enable Receive Side Scaling; adapter may restart')) {
            $whatIfCount++
            continue
        }
        [void]$approvedTargets.Add($target)
    }
    if ($approvedTargets.Count -eq 0) {
        if ($whatIfCount -gt 0) {
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'RSS state was not changed.')
        }
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'No adapter was selected by ShouldProcess.')
    }

    $targets = @($approvedTargets)

    Ensure-BestEffortRestorePoint
    $approvedTargetGuids = @($targets | ForEach-Object { [string]$_.InterfaceGuid })
    $freshTargets = @(Get-RssCandidateAdapters | Where-Object { $approvedTargetGuids -icontains $_.InterfaceGuid })
    if ($freshTargets.Count -ne $targets.Count -or
        -not (Test-RestoreStateEquivalent -Kind 'Rss' -Left $freshTargets -Right $targets)) {
        $message = 'RSS adapter identity or state changed after consent; no adapter was modified. Review the new state and run again.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    $targets = $freshTargets
    $record = New-ChangeRecord -Operation $Operation -BeforeState $targets -RestoreKind 'Rss'
    try {
        foreach ($adapter in $targets) {
            $adapterGuid = [guid]$adapter.InterfaceGuid
            $exactAdapter = @(NetAdapter\Get-NetAdapter -ErrorAction Stop | Where-Object {
                $_.HardwareInterface -eq $true -and ([guid]$_.InterfaceGuid) -eq $adapterGuid
            })
            if ($exactAdapter.Count -ne 1) {
                throw ("The exact physical network adapter '{0}' is no longer present." -f $adapter.Name)
            }
            $exactAdapter[0] | NetAdapter\Enable-NetAdapterRss -Confirm:$false -ErrorAction Stop
        }
        $targetGuids = @($targets | ForEach-Object { [string]$_.InterfaceGuid })
        $after = @()
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            $after = @(Get-RssCandidateAdapters | Where-Object { $targetGuids -icontains $_.InterfaceGuid })
            if ($after.Count -eq $targets.Count -and @($after | Where-Object { -not $_.Enabled }).Count -eq 0) {
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if ($after.Count -ne $targets.Count -or @($after | Where-Object { -not $_.Enabled }).Count -gt 0) {
            throw 'Post-change RSS verification failed.'
        }
        $message = "Enabled RSS on {0:N0} wired physical adapter(s)." -f $targets.Count
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $after -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message -RestartRequired $false)
    }
    catch {
        $primaryError = $_.Exception.Message
        $targetGuids = @($targets | ForEach-Object { [string]$_.InterfaceGuid })
        $failureMessage = Complete-ReversibleFailure -Record $record -PrimaryError $primaryError `
            -Kind 'Rss' -BeforeState $targets `
            -RollbackAction { Restore-RssState -BeforeState $targets } `
            -ReadCurrentState { @(Get-RssCandidateAdapters | Where-Object { $targetGuids -icontains $_.InterfaceGuid }) }
        throw $failureMessage
    }
}

function Get-PowerPerformanceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$OsInfo)

    if ($OsInfo.Family -eq 'Windows 11') {
        Initialize-NativeMethods
        return [pscustomobject][ordered]@{
            Mechanism = 'Windows11ACPowerMode'
            Guid      = $script:NativeMethods.GetACPowerMode().ToString()
        }
    }

    return [pscustomobject][ordered]@{
        Mechanism = 'Windows10PowerPlan'
        Guid      = Get-ActivePowerPlanGuid
    }
}

function Restore-PowerPerformanceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $BeforeState)

    switch ([string]$BeforeState.Mechanism) {
        'Windows11ACPowerMode' {
            Initialize-NativeMethods
            $guid = [guid]([string]$BeforeState.Guid)
            $script:NativeMethods.SetACPowerMode($guid)
        }
        'Windows10PowerPlan' {
            $powercfgPath = Get-TrustedSystemExecutable -Name 'powercfg.exe'
            $output = @(& $powercfgPath /setactive ([string]$BeforeState.Guid) 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw ("powercfg restore failed: {0}" -f ($output -join ' '))
            }
        }
        default {
            throw ("Unknown power restore mechanism '{0}'." -f $BeforeState.Mechanism)
        }
    }
}

function Invoke-PowerPerformanceOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation,
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo
    )

    $bestPerformanceGuid = 'ded574b5-45a0-4f42-8737-46345c09c238'
    $highPerformancePlanGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    $before = Get-PowerPerformanceState -OsInfo $OsInfo
    $desiredGuid = if ($before.Mechanism -eq 'Windows11ACPowerMode') { $bestPerformanceGuid } else { $highPerformancePlanGuid }

    if ([string]$before.Guid -ieq $desiredGuid) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message 'Best/High performance is already selected for the applicable mechanism.')
    }
    if (-not $script:IsWhatIf -and $before.Mechanism -eq 'Windows10PowerPlan') {
        $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
        if ($null -ne $powerPlanBlock) {
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $powerPlanBlock)
        }
    }

    $batteryNote = if ($OsInfo.HasBattery) { 'A battery is present.' } else { 'No battery was detected.' }
    $context = "Mechanism={0}; current={1}; {2}" -f $before.Mechanism, $before.Guid, $batteryNote
    if (-not (Request-OperationConsent -Operation $Operation -AdditionalContext $context)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }
    $powerAction = if ($before.Mechanism -eq 'Windows11ACPowerMode') { 'Select Best performance for AC power' } else { 'Activate the existing High performance plan for this user' }
    if (-not (Test-ShouldProcessOperation -Target 'Windows power configuration' -Action $powerAction)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Power configuration was not changed.')
    }
    if ($before.Mechanism -eq 'Windows10PowerPlan') {
        $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
        if ($null -ne $powerPlanBlock) {
            return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $powerPlanBlock)
        }
    }

    Ensure-BestEffortRestorePoint
    $freshBefore = Get-PowerPerformanceState -OsInfo $OsInfo
    if (-not (Test-RestoreStateEquivalent -Kind 'PowerPerformance' -Left $freshBefore -Right $before)) {
        $message = 'Power configuration changed after consent; it was not modified. Review the new state and run again.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    $before = $freshBefore
    $record = New-ChangeRecord -Operation $Operation -BeforeState $before -RestoreKind 'PowerPerformance'
    try {
        if ($before.Mechanism -eq 'Windows11ACPowerMode') {
            $guid = [guid]$bestPerformanceGuid
            $script:NativeMethods.SetACPowerMode($guid)
        }
        else {
            $existingPlan = Get-ExistingHighPerformancePlan
            if ($null -eq $existingPlan) {
                throw 'The existing High performance plan is no longer available.'
            }
            $powercfgPath = Get-TrustedSystemExecutable -Name 'powercfg.exe'
            # The user may unplug the computer while consent, restore-point
            # creation, or journal writes are in progress. Recheck as close to
            # the actual mutation as possible.
            $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
            if ($null -ne $powerPlanBlock) {
                $message = '{0} No power-plan mutation was attempted.' -f $powerPlanBlock
                Complete-ChangeRecord -Record $record -Status 'RolledBack' -AfterState $before -Message $message
                Write-Log -Level 'WARN' -Message $message
                return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
            }
            $output = @(& $powercfgPath /setactive $existingPlan 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw ("powercfg /setactive failed: {0}" -f ($output -join ' '))
            }
        }

        $after = Get-PowerPerformanceState -OsInfo $OsInfo
        if ([string]$after.Guid -ine $desiredGuid) {
            throw 'Post-change power configuration verification failed.'
        }
        $message = 'Best/High performance was selected using the supported mechanism.'
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $after -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        $primaryError = $_.Exception.Message
        $failureMessage = Complete-ReversibleFailure -Record $record -PrimaryError $primaryError `
            -Kind 'PowerPerformance' -BeforeState $before `
            -RollbackAction { Restore-PowerPerformanceState -BeforeState $before } `
            -ReadCurrentState { Get-PowerPerformanceState -OsInfo $OsInfo }
        throw $failureMessage
    }
}

function Restore-ClientAnimationsState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $BeforeState)

    Initialize-NativeMethods
    $script:NativeMethods.SetClientAreaAnimation([bool]$BeforeState.Enabled)
    $observed = [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
    if (-not (Test-RestoreStateEquivalent -Kind 'ClientAnimations' -Left $observed -Right $BeforeState)) {
        throw 'Client-area animation post-restore verification failed.'
    }
}

function Invoke-ClientAnimationsOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    Initialize-NativeMethods
    $before = [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
    if (-not $before.Enabled) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'AlreadyCompliant' -Message 'Client-area animations are already disabled.')
    }

    if (-not (Request-OperationConsent -Operation $Operation -AdditionalContext 'Client-area animations are enabled.')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }
    if (-not (Test-ShouldProcessOperation -Target 'Current user visual effects' -Action 'Disable client-area animations')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Visual effects were not changed.')
    }

    Ensure-BestEffortRestorePoint
    $freshBefore = [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
    if (-not (Test-RestoreStateEquivalent -Kind 'ClientAnimations' -Left $freshBefore -Right $before)) {
        $message = 'Client-area animation state changed after consent; it was not modified. Review the new state and run again.'
        Write-Log -Level 'WARN' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Blocked' -Message $message)
    }
    $before = $freshBefore
    $record = New-ChangeRecord -Operation $Operation -BeforeState $before -RestoreKind 'ClientAnimations'
    try {
        $script:NativeMethods.SetClientAreaAnimation($false)
        $after = [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
        if ($after.Enabled) {
            throw 'Post-change animation verification failed.'
        }
        $message = 'Client-area animations were disabled for the current user.'
        Complete-ChangeRecord -Record $record -Status 'Succeeded' -AfterState $after -Message $message
        Write-Log -Level 'SUCCESS' -Message $message
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Changed' -Message $message)
    }
    catch {
        $primaryError = $_.Exception.Message
        $failureMessage = Complete-ReversibleFailure -Record $record -PrimaryError $primaryError `
            -Kind 'ClientAnimations' -BeforeState $before `
            -RollbackAction { Restore-ClientAnimationsState -BeforeState $before } `
            -ReadCurrentState {
                [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
            }
        throw $failureMessage
    }
}

function Invoke-OpenSettingsOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [pscustomobject]$Operation)

    if (-not (Request-OperationConsent -Operation $Operation)) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Skipped' -Message 'Declined by consent policy.')
    }

    $uri = switch ($Operation.Kind) {
        'OpenStartupApps'  { 'ms-settings:startupapps' }
        'OpenStorageSense' { 'ms-settings:storagepolicies' }
        default { throw ("Unsupported Settings operation '{0}'." -f $Operation.Kind) }
    }

    if (-not (Test-ShouldProcessOperation -Target $uri -Action 'Open Windows Settings')) {
        return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'WhatIf' -Message 'Settings was not opened.')
    }

    Microsoft.PowerShell.Management\Start-Process -FilePath $uri -ErrorAction Stop
    $message = 'Windows Settings was opened; no setting was changed automatically.'
    Write-Log -Level 'SUCCESS' -Message ("{0}: {1}" -f $Operation.Id, $message)
    return (Add-Result -Id $Operation.Id -Category $Operation.Category -Status 'Opened' -Message $message)
}

function Invoke-Operation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation,
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo
    )

    switch ($Operation.Kind) {
        'TempFolder'            { return (Invoke-TempFolderOperation -Operation $Operation) }
        'Service'               { return (Invoke-ServiceOperation -Operation $Operation) }
        'DeliveryOptimization'  { return (Invoke-DeliveryOptimizationOperation -Operation $Operation) }
        'ComponentStore'        { return (Invoke-ComponentStoreOperation -Operation $Operation) }
        'OptimizeVolumes'       { return (Invoke-OptimizeVolumesOperation -Operation $Operation) }
        'TcpAutoTuning'         { return (Invoke-TcpAutoTuningOperation -Operation $Operation) }
        'Rss'                   { return (Invoke-RssOperation -Operation $Operation) }
        'PowerPerformance'      { return (Invoke-PowerPerformanceOperation -Operation $Operation -OsInfo $OsInfo) }
        'ClientAnimations'      { return (Invoke-ClientAnimationsOperation -Operation $Operation) }
        'OpenStartupApps'       { return (Invoke-OpenSettingsOperation -Operation $Operation) }
        'OpenStorageSense'      { return (Invoke-OpenSettingsOperation -Operation $Operation) }
        default                 { throw ("No handler exists for operation kind '{0}'." -f $Operation.Kind) }
    }
}

function Get-AuditSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo,
        [Parameter(Mandatory = $true)] [object[]]$Catalog
    )

    $collectors = New-Object System.Collections.ArrayList
    $selectedCategories = @($Catalog | ForEach-Object { [string]$_.Category } | Select-Object -Unique)
    $selectedKinds = @($Catalog | ForEach-Object { [string]$_.Kind } | Select-Object -Unique)
    $collectVolumes = ($selectedCategories -icontains 'Cleanup') -or ($selectedCategories -icontains 'Storage')
    $collectStartup = $selectedCategories -icontains 'Startup'
    $collectServices = $selectedCategories -icontains 'Services'
    $collectTcp = $selectedKinds -icontains 'TcpAutoTuning'
    $collectRss = $selectedKinds -icontains 'Rss'
    $collectPower = $selectedKinds -icontains 'PowerPerformance'
    $collectAnimations = $selectedKinds -icontains 'ClientAnimations'

    $volumes = @()
    if ($collectVolumes) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting storage information' -PercentComplete 15
        try {
            if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'Storage\Get-Volume' -ErrorAction SilentlyContinue)) {
                throw 'Storage\Get-Volume is unavailable.'
            }
            $volumes = @(Storage\Get-Volume -ErrorAction Stop | Where-Object { $null -ne $_.DriveLetter } | ForEach-Object {
                [pscustomobject][ordered]@{
                    DriveLetter    = [string]$_.DriveLetter
                    FileSystem     = [string]$_.FileSystem
                    DriveType      = [string]$_.DriveType
                    HealthStatus   = [string]$_.HealthStatus
                    SizeBytes      = [long]$_.Size
                    FreeBytes      = [long]$_.SizeRemaining
                    FreePercent    = if ([long]$_.Size -gt 0) { [math]::Round(([long]$_.SizeRemaining / [long]$_.Size) * 100, 2) } else { $null }
                }
            })
            $missingAuditLetters = @()
            if ($null -ne $VolumeDriveLetter -and @($VolumeDriveLetter).Count -gt 0) {
                $auditLetters = @($VolumeDriveLetter | ForEach-Object { $_.TrimEnd(':').ToUpperInvariant() } | Select-Object -Unique)
                $presentAuditLetters = @($volumes | ForEach-Object { $_.DriveLetter.ToUpperInvariant() })
                $missingAuditLetters = @($auditLetters | Where-Object { $presentAuditLetters -notcontains $_ })
                $volumes = @($volumes | Where-Object { $auditLetters -contains $_.DriveLetter.ToUpperInvariant() })
            }
            $volumeStatus = if ($missingAuditLetters.Count -gt 0) { 'Partial' } else { 'Succeeded' }
            $volumeError = if ($missingAuditLetters.Count -gt 0) { 'Requested drive letter(s) were not found: {0}' -f ($missingAuditLetters -join ', ') } else { $null }
            [void]$collectors.Add([pscustomobject]@{ Name = 'Volumes'; Status = $volumeStatus; Count = $volumes.Count; Error = $volumeError })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'Volumes'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }

    $startupApps = @()
    if ($collectStartup) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting startup applications' -PercentComplete 35
        try {
            $startupApps = @(CimCmdlets\Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name     = [string]$_.Name
                    Command  = if ($IncludeStartupCommandLines) { [string]$_.Command } else { $null }
                    Location = if ($IncludeSensitiveAuditData) { [string]$_.Location } else { $null }
                    User     = if ($IncludeSensitiveAuditData) { [string]$_.User } else { $null }
                }
            })
            [void]$collectors.Add([pscustomobject]@{ Name = 'StartupApplications'; Status = 'Succeeded'; Count = $startupApps.Count; Error = $null })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'StartupApplications'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }

    $serviceStates = @()
    $criticalServices = @()
    if ($collectServices) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting allowlisted service state' -PercentComplete 55
        try {
            $allServices = @(CimCmdlets\Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
            $serviceStates = @($Catalog | Where-Object { $_.Kind -eq 'Service' } | ForEach-Object {
                $operation = $_
                $service = @($allServices | Where-Object { $_.Name -ieq $operation.ServiceName } | Select-Object -First 1)
                $service = if ($service.Count -eq 1) { $service[0] } else { $null }
                [pscustomobject][ordered]@{
                    Name        = $operation.ServiceName
                    DisplayName = $operation.DisplayName.Replace('Disable ', '')
                    Installed   = ($null -ne $service)
                    StartMode   = if ($null -ne $service) { [string]$service.StartMode } else { $null }
                    State       = if ($null -ne $service) { [string]$service.State } else { $null }
                }
            })
            $criticalServices = @(@('WinDefend', 'mpssvc', 'BFE', 'wuauserv', 'BITS', 'EventLog', 'SysMain') | ForEach-Object {
                $name = $_
                $service = @($allServices | Where-Object { $_.Name -ieq $name } | Select-Object -First 1)
                $service = if ($service.Count -eq 1) { $service[0] } else { $null }
                [pscustomobject][ordered]@{
                    Name      = $name
                    Installed = ($null -ne $service)
                    StartMode = if ($null -ne $service) { [string]$service.StartMode } else { $null }
                    State     = if ($null -ne $service) { [string]$service.State } else { $null }
                }
            })
            [void]$collectors.Add([pscustomobject]@{ Name = 'Services'; Status = 'Succeeded'; Count = $serviceStates.Count; Error = $null })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'Services'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }

    $tcpSettings = @()
    if ($collectTcp) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting TCP state' -PercentComplete 70
        try {
            if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'NetTCPIP\Get-NetTCPSetting' -ErrorAction SilentlyContinue)) {
                throw 'NetTCPIP\Get-NetTCPSetting is unavailable.'
            }
            $tcpSettings = @(Get-TcpAutoTuningState)
            [void]$collectors.Add([pscustomobject]@{ Name = 'TcpSettings'; Status = 'Succeeded'; Count = $tcpSettings.Count; Error = $null })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'TcpSettings'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }
    $rssAdapters = @()
    if ($collectRss) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting RSS state' -PercentComplete 75
        try {
            if (-not (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Get-NetAdapter' -ErrorAction SilentlyContinue) -or
                -not (Microsoft.PowerShell.Core\Get-Command -Name 'NetAdapter\Get-NetAdapterRss' -ErrorAction SilentlyContinue)) {
                throw 'NetAdapter RSS cmdlets are unavailable.'
            }
            $rssAdapters = @(Get-RssCandidateAdapters)
            $missingAuditAdapterGuids = @()
            if ($null -ne $AdapterInterfaceGuid -and @($AdapterInterfaceGuid).Count -gt 0) {
                $auditAdapterGuids = @($AdapterInterfaceGuid | ForEach-Object { $_.ToString() })
                $presentAuditAdapterGuids = @($rssAdapters | ForEach-Object { [string]$_.InterfaceGuid })
                $missingAuditAdapterGuids = @($auditAdapterGuids | Where-Object { $presentAuditAdapterGuids -inotcontains $_ })
                $rssAdapters = @($rssAdapters | Where-Object { $auditAdapterGuids -icontains $_.InterfaceGuid })
            }
            $rssDiagnostics = $script:LastRssCandidateDiagnostics
            $rssIssues = New-Object System.Collections.ArrayList
            if (-not $rssDiagnostics.RouteDetectionSucceeded) {
                [void]$rssIssues.Add('Default-route detection was unavailable.')
            }
            if (@($rssDiagnostics.QueryFailures).Count -gt 0) {
                [void]$rssIssues.Add(("RSS capability queries failed for {0} physical adapter(s)." -f @($rssDiagnostics.QueryFailures).Count))
            }
            if ($missingAuditAdapterGuids.Count -gt 0) {
                [void]$rssIssues.Add(("Requested adapter GUID(s) were not eligible or found: {0}" -f ($missingAuditAdapterGuids -join ', ')))
            }
            $rssStatus = if ($rssIssues.Count -gt 0) { 'Partial' } else { 'Succeeded' }
            [void]$collectors.Add([pscustomobject]@{ Name = 'RssAdapters'; Status = $rssStatus; Count = $rssAdapters.Count; Error = $(if ($rssIssues.Count -gt 0) { $rssIssues -join ' ' } else { $null }) })
            if (-not $IncludeSensitiveAuditData) {
                $rssAdapters = @($rssAdapters | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Name                 = $null
                        InterfaceGuid        = $null
                        InterfaceIndex       = $_.InterfaceIndex
                        InterfaceDescription = $_.InterfaceDescription
                        Status               = $_.Status
                        IsDefaultRoute       = $_.IsDefaultRoute
                        Enabled              = $_.Enabled
                    }
                })
            }
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'RssAdapters'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }
    $powerState = $null
    if ($collectPower) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting power state' -PercentComplete 82
        try {
            if (-not (Test-IsInteractiveUserContext -UserSid ([string]$OsInfo.CurrentUserSid))) {
                throw 'User power preference was not collected outside an interactive signed-in user context.'
            }
            $powerState = Get-PowerPerformanceState -OsInfo $OsInfo
            [void]$collectors.Add([pscustomobject]@{ Name = 'PowerState'; Status = 'Succeeded'; Count = 1; Error = $null })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'PowerState'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }
    $animationState = $null
    if ($collectAnimations) {
        Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Status 'Collecting animation state' -PercentComplete 86
        try {
            if (-not (Test-IsInteractiveUserContext -UserSid ([string]$OsInfo.CurrentUserSid))) {
                throw 'Client animation state was not collected outside an interactive signed-in user context.'
            }
            Initialize-NativeMethods
            $animationState = [pscustomobject][ordered]@{ Enabled = $script:NativeMethods.GetClientAreaAnimation() }
            [void]$collectors.Add([pscustomobject]@{ Name = 'ClientAnimations'; Status = 'Succeeded'; Count = 1; Error = $null })
        }
        catch {
            [void]$collectors.Add([pscustomobject]@{ Name = 'ClientAnimations'; Status = 'Failed'; Count = 0; Error = $_.Exception.Message })
        }
    }

    $operationAvailability = @($Catalog | ForEach-Object {
        $availability = Get-OperationAvailability -Operation $_ -OsInfo $OsInfo
        [pscustomobject][ordered]@{
            Id          = $_.Id
            Category    = $_.Category
            Risk        = $_.Risk
            Recommended = $_.Recommended
            Reversible  = $_.Reversible
            Available   = $availability.Available
            Reason      = $availability.Reason
        }
    })

    $auditStatus = if (@($collectors | Where-Object { $_.Status -ne 'Succeeded' }).Count -gt 0) { 'Partial' } else { 'Complete' }
    if ($auditStatus -eq 'Partial') { Set-PartialExitCode }
    $auditOperatingSystem = [pscustomobject][ordered]@{
        Caption           = $OsInfo.Caption
        Version           = $OsInfo.Version
        BuildNumber       = $OsInfo.BuildNumber
        Family            = $OsInfo.Family
        ProductType       = $OsInfo.ProductType
        OSArchitecture    = $OsInfo.OSArchitecture
        LastBootUpTimeUtc = $OsInfo.LastBootUpTimeUtc
        ComputerName      = if ($IncludeSensitiveAuditData) { $OsInfo.ComputerName } else { $null }
        DeviceIdentityHash = if ($IncludeSensitiveAuditData) { $OsInfo.DeviceIdentityHash } else { $null }
        DeviceIdentityReliable = $OsInfo.DeviceIdentityReliable
        CurrentUserSid    = if ($IncludeSensitiveAuditData) { $OsInfo.CurrentUserSid } else { $null }
        Manufacturer      = $OsInfo.Manufacturer
        Model             = $OsInfo.Model
        PartOfDomain      = $OsInfo.PartOfDomain
        AzureAdJoined     = $OsInfo.AzureAdJoined
        EnterpriseJoined  = $OsInfo.EnterpriseJoined
        WorkplaceJoined   = $OsInfo.WorkplaceJoined
        MdmEnrolled       = $OsInfo.MdmEnrolled
        ConfigMgrDetected = $OsInfo.ConfigMgrDetected
        ManagementSignals = $OsInfo.ManagementSignals
        ManagementDetectionReliable = $OsInfo.ManagementDetectionReliable
        IsManagedDevice   = $OsInfo.IsManagedDevice
        Domain            = if ($IncludeSensitiveAuditData) { $OsInfo.Domain } else { $null }
        TotalMemoryBytes  = $OsInfo.TotalMemoryBytes
        ProcessorCount    = $OsInfo.ProcessorCount
        HasBattery        = $OsInfo.HasBattery
        BatteryDetectionReliable = $OsInfo.BatteryDetectionReliable
        AcLineStatus      = $OsInfo.AcLineStatus
        AcLineStatusReliable = $OsInfo.AcLineStatusReliable
        BatteryLifePercent = $OsInfo.BatteryLifePercent
    }
    Write-Progress -Id 1 -Activity 'Auditing Windows performance configuration' -Completed
    return [pscustomobject][ordered]@{
        SchemaVersion         = 1
        Tool                  = '{0} {1}' -f $script:ScriptName, $script:ScriptVersion
        GeneratedUtc          = [DateTime]::UtcNow.ToString('o')
        AuditStatus           = $auditStatus
        Collectors            = @($collectors)
        SensitiveDataIncluded = [bool]$IncludeSensitiveAuditData
        StartupCommandsIncluded = [bool]$IncludeStartupCommandLines
        SelectedOperationIds    = @($Catalog | ForEach-Object { [string]$_.Id })
        OperatingSystem       = $auditOperatingSystem
        Volumes               = $volumes
        StartupApplications   = $startupApps
        AllowlistedServices   = $serviceStates
        ProtectedCoreServices = @($criticalServices)
        TcpSettings           = $tcpSettings
        RssWiredAdapters      = $rssAdapters
        PowerState            = $powerState
        ClientAnimationsState = $animationState
        Operations            = $operationAvailability
        Notes                 = @(
            'Manual/Stopped services generally consume no active CPU and may provide no gain if disabled.',
            'A low-free-space volume can reduce performance; cleanup benefit is workload-dependent.',
            'Startup command lines are redacted by default; use -IncludeStartupCommandLines only when needed.',
            'Computer name, user SID, device identity hash, domain, startup location/user, and stable adapter identity are redacted unless -IncludeSensitiveAuditData is used.',
            'Collectors are scoped to the selected operation categories and kinds; an unfiltered Audit selects the full catalog.',
            'Third-party RMM and every possible management agent cannot be detected generically; confirm local change control before Apply/Restore.',
            'Windows 10 standard support ended 2025-10-14; verify LTSC or ESU status if it remains deployed.',
            'No optimization was applied by Audit mode.'
        )
    }
}

function Write-AuditReport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Snapshot)

    $dataRoot = Get-DefaultDataRoot
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $reportDirectory = Join-Path $dataRoot 'Reports'
        New-SafeDirectory -Path $reportDirectory
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $script:ReportPath = Join-Path $reportDirectory ("WinOptimize-audit-{0}.json" -f $stamp)
    }
    else {
        $script:ReportPath = Assert-SafeOperationalFilePath -Path $ReportPath -Purpose 'ReportPath'
        Assert-PathWithinDataRoot -Path $script:ReportPath -DataRoot $dataRoot -Purpose 'audit report'
        if (Test-Path -LiteralPath $script:ReportPath -PathType Container) {
            throw 'ReportPath must be a file path, not a directory.'
        }
        $reportDirectory = Split-Path -Parent $script:ReportPath
        if ([string]::IsNullOrWhiteSpace($reportDirectory)) {
            throw 'ReportPath must include a valid parent directory.'
        }
        Assert-PathWithinDataRoot -Path $reportDirectory -DataRoot $dataRoot -Purpose 'audit-report directory' -AllowEqual
        Assert-OperationalPathOutsideTempRoots -Path $script:ReportPath -Purpose 'Audit report'
        New-SafeDirectory -Path $reportDirectory
    }

    $script:ReportPath = Assert-SafeOperationalFilePath -Path $script:ReportPath -Purpose 'Audit report path'
    Assert-OperationalPathOutsideTempRoots -Path $script:ReportPath -Purpose 'Audit report'
    if (Test-PathContainsReparsePoint -Path (Split-Path -Parent $script:ReportPath)) {
        throw 'Audit-report directory or one of its parents is a reparse point.'
    }
    Set-RestrictedDirectoryAcl -Path (Split-Path -Parent $script:ReportPath) -IncludeCurrentUser:(-not (Test-IsAdministrator))
    if (Test-Path -LiteralPath $script:ReportPath) {
        throw ("Refusing to overwrite an existing report path: {0}" -f $script:ReportPath)
    }

    $json = $Snapshot | ConvertTo-Json -Depth 16
    $temporaryPath = '{0}.{1}.tmp' -f $script:ReportPath, ([guid]::NewGuid().ToString('N'))
    [void](Assert-SafeOperationalFilePath -Path $temporaryPath -Purpose 'Temporary audit-report path')
    try {
        Write-NewRestrictedTextFile -Path $temporaryPath -Text $json -IncludeCurrentUser:(-not (Test-IsAdministrator))
        [IO.File]::Move($temporaryPath, $script:ReportPath)
        Set-RestrictedFileAcl -Path $script:ReportPath -IncludeCurrentUser:(-not (Test-IsAdministrator))
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
        }
    }

    return $script:ReportPath
}

function Assert-JsonBoolean {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] $Value,
        [Parameter(Mandatory = $true)] [string]$Description
    )

    if ($Value -isnot [bool]) {
        throw ("Manifest value '{0}' must be a JSON Boolean." -f $Description)
    }
}

function Assert-ServiceFileEvidenceSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Evidence,
        [Parameter(Mandatory = $true)] [ValidateSet('.exe', '.dll')] [string]$ExpectedExtension,
        [Parameter(Mandatory = $true)] [string]$Label
    )

    $path = [string]$Evidence.Path
    $sha256 = [string]$Evidence.Sha256
    $signatureType = [string]$Evidence.SignatureType
    $thumbprint = [string]$Evidence.SignerThumbprint
    $subject = [string]$Evidence.SignerSubject
    if ([string]::IsNullOrWhiteSpace($path) -or $path.Length -gt 32768 -or
        [IO.Path]::GetExtension($path) -ine $ExpectedExtension -or
        -not (Test-IsApprovedServiceComponentPath -Path $path) -or
        $sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$Evidence.Length -le 0 -or
        [string]$Evidence.SignatureStatus -cne 'Valid' -or
        [string]::IsNullOrWhiteSpace($signatureType) -or $signatureType.Length -gt 64 -or
        $thumbprint -notmatch '^[0-9a-f]{40,128}$' -or
        [string]::IsNullOrWhiteSpace($subject) -or $subject.Length -gt 2048 -or
        $subject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw ("Manifest service file evidence '{0}' is invalid." -f $Label)
    }
    Assert-JsonBoolean -Value $Evidence.IsOsBinary -Description "$Label.IsOsBinary"
    if (-not [bool]$Evidence.IsOsBinary) {
        throw ("Manifest service file evidence '{0}' is not marked as a Windows OS binary." -f $Label)
    }
}

function Assert-RestoreStateSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Kind,
        [Parameter(Mandatory = $false)] $State,
        [Parameter(Mandatory = $true)] [pscustomobject]$Operation,
        [Parameter(Mandatory = $true)] [string]$Label
    )

    if ($null -eq $State) {
        throw ("Manifest {0} state is missing for '{1}'." -f $Label, $Operation.Id)
    }

    switch ($Kind) {
        'Service' {
            $name = [string]$State.Name
            if ($script:CriticalServiceDenylist -icontains $name -or $name -ine $Operation.ServiceName) {
                throw ("Manifest service target '{0}' is not permitted." -f $name)
            }
            if (@('Auto', 'Manual', 'Disabled') -notcontains ([string]$State.StartMode)) {
                throw ("Manifest service start mode is invalid for '{0}'." -f $name)
            }
            if (@('Running', 'Stopped') -notcontains ([string]$State.State)) {
                throw ("Manifest service state is invalid for '{0}'." -f $name)
            }
            $binaryPathName = [string]$State.BinaryPathName
            $accountName = [string]$State.AccountName
            $serviceType = [string]$State.ServiceType
            if ([string]::IsNullOrWhiteSpace($binaryPathName) -or $binaryPathName.Length -gt 32768 -or $binaryPathName -match '[\x00\r\n]' -or
                [string]::IsNullOrWhiteSpace($accountName) -or $accountName.Length -gt 512 -or $accountName -match '[\x00\r\n]' -or
                [string]::IsNullOrWhiteSpace($serviceType) -or $serviceType.Length -gt 256 -or $serviceType -match '[\x00\r\n]') {
                throw ("Manifest service identity metadata is invalid for '{0}'." -f $name)
            }
            $identity = $State.Identity
            if ($null -eq $identity -or
                @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -notcontains ([string]$identity.AccountSid) -and
                -not ([string]$identity.AccountSid).StartsWith('S-1-5-80-', [StringComparison]::OrdinalIgnoreCase)) {
                throw ("Manifest service account identity is invalid for '{0}'." -f $name)
            }
            $registryType = [uint32]$identity.RegistryType
            if (@([uint32]0x10, [uint32]0x20) -notcontains $registryType) {
                throw ("Manifest service registry type is invalid for '{0}'." -f $name)
            }
            $expectedAccountSid = Resolve-ServiceAccountSid -AccountName $accountName -ServiceName $name
            if ([string]$identity.AccountSid -cne $expectedAccountSid) {
                throw ("Manifest service account name/SID mapping is invalid for '{0}'." -f $name)
            }
            Assert-ServiceFileEvidenceSafe -Evidence $identity.Image -ExpectedExtension '.exe' -Label "$Label.Identity.Image"
            if ($null -ne $identity.ServiceDll) {
                Assert-ServiceFileEvidenceSafe -Evidence $identity.ServiceDll -ExpectedExtension '.dll' -Label "$Label.Identity.ServiceDll"
            }
            $systemSvchost = Get-SafeFullPath -Path ([IO.Path]::Combine([Environment]::SystemDirectory, 'svchost.exe'))
            if (($registryType -eq [uint32]0x20 -and [string]$identity.Image.Path -ine $systemSvchost) -or
                ([IO.Path]::GetFileName([string]$identity.Image.Path) -ieq 'svchost.exe' -and $null -eq $identity.ServiceDll) -or
                ([IO.Path]::GetFileName([string]$identity.Image.Path) -ine 'svchost.exe' -and $null -ne $identity.ServiceDll)) {
                throw ("Manifest service host/component mapping is invalid for '{0}'." -f $name)
            }
            Assert-JsonBoolean -Value $State.DelayedAutoStart -Description "$Label.DelayedAutoStart"
            Assert-JsonBoolean -Value $State.Started -Description "$Label.Started"
            if ((([string]$State.State -eq 'Running') -ne [bool]$State.Started) -or
                ([bool]$State.DelayedAutoStart -and [string]$State.StartMode -ne 'Auto') -or
                ([string]$State.StartMode -eq 'Disabled' -and [bool]$State.Started)) {
                throw ("Manifest service state flags are unsupported by this rollback model for '{0}'." -f $name)
            }
        }
        'TcpAutoTuning' {
            $settings = @($State)
            if ($settings.Count -lt 1 -or $settings.Count -gt 16) {
                throw 'Manifest TCP state has an invalid number of templates.'
            }
            $allowedTemplates = @('InternetCustom', 'DatacenterCustom')
            $allowedLevels = @('Disabled', 'HighlyRestricted', 'Restricted', 'Normal', 'Experimental')
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($setting in $settings) {
                if ($allowedTemplates -notcontains ([string]$setting.SettingName) -or
                    $allowedLevels -notcontains ([string]$setting.AutoTuningLevelLocal) -or
                    @('Local', 'GroupPolicy') -notcontains ([string]$setting.AutoTuningLevelEffective) -or
                    @($allowedLevels + 'NotConfigured') -notcontains ([string]$setting.AutoTuningLevelGroupPolicy) -or
                    (([string]$setting.AutoTuningLevelEffective -eq 'Local') -and
                     ([string]$setting.AutoTuningLevelGroupPolicy -ne 'NotConfigured')) -or
                    (([string]$setting.AutoTuningLevelEffective -eq 'GroupPolicy') -and
                     ([string]$setting.AutoTuningLevelGroupPolicy -eq 'NotConfigured')) -or
                    -not $seen.Add([string]$setting.SettingName)) {
                    throw ("Manifest contains an invalid or duplicate TCP state for '{0}'." -f $setting.SettingName)
                }
            }
        }
        'Rss' {
            $adapters = @($State)
            if ($adapters.Count -lt 1 -or $adapters.Count -gt 64) {
                throw 'Manifest RSS state has an invalid number of adapters.'
            }
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($adapter in $adapters) {
                $name = [string]$adapter.Name
                $guidText = [string]$adapter.InterfaceGuid
                $parsedGuid = [guid]::Empty
                if ([string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 256 -or $name -match '[\*\?\[]' -or
                    -not [guid]::TryParse($guidText, [ref]$parsedGuid) -or $parsedGuid -eq [guid]::Empty -or
                    -not $seen.Add($parsedGuid.ToString())) {
                    throw 'Manifest contains an invalid, wildcarded, or duplicate network-adapter identity.'
                }
                Assert-JsonBoolean -Value $adapter.Enabled -Description "$Label.Enabled"
            }
        }
        'PowerPerformance' {
            $mechanism = [string]$State.Mechanism
            $guidText = [string]$State.Guid
            $parsedGuid = [guid]::Empty
            if (-not [guid]::TryParse($guidText, [ref]$parsedGuid)) {
                throw 'Manifest contains an invalid power GUID.'
            }
            if ($mechanism -eq 'Windows11ACPowerMode') {
                $allowedPowerModes = @(
                    '00000000-0000-0000-0000-000000000000',
                    '961cc777-2547-4f9d-8174-7d86181b8a7a',
                    'ded574b5-45a0-4f42-8737-46345c09c238'
                )
                if ($allowedPowerModes -notcontains $parsedGuid.ToString()) {
                    throw 'Manifest contains an unsupported Windows 11 power mode.'
                }
            }
            elseif ($mechanism -ne 'Windows10PowerPlan') {
                throw ("Manifest contains an invalid power mechanism '{0}'." -f $mechanism)
            }
        }
        'ClientAnimations' {
            Assert-JsonBoolean -Value $State.Enabled -Description "$Label.Enabled"
        }
        default {
            throw ("Manifest contains an unsupported state kind '{0}'." -f $Kind)
        }
    }
}

function Assert-RestoreRecordSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [object[]]$Catalog
    )

    $operation = @($Catalog | Where-Object { $_.Id -ieq ([string]$Record.Id) })
    if ($operation.Count -ne 1) {
        throw ("Manifest contains unknown operation ID '{0}'." -f $Record.Id)
    }
    $operation = $operation[0]

    Assert-JsonBoolean -Value $Record.Reversible -Description 'Reversible'
    if ([bool]$Record.Reversible -ne [bool]$operation.Reversible -or [string]$Record.Category -cne [string]$operation.Category) {
        throw ("Manifest metadata does not match catalog operation '{0}'." -f $Record.Id)
    }

    $allowedStatuses = if ($operation.Reversible) {
        @('Prepared', 'Succeeded', 'RolledBack', 'RollbackFailed')
    }
    else {
        @('Prepared', 'Succeeded', 'Partial', 'Failed')
    }
    if ($allowedStatuses -notcontains ([string]$Record.Status)) {
        throw ("Manifest record status is invalid for '{0}'." -f $Record.Id)
    }

    $restoreStatusProperty = $Record.PSObject.Properties['RestoreStatus']
    if ($null -ne $restoreStatusProperty -and
        @('Prepared', 'Succeeded', 'Failed', 'AlreadyRestored', 'RolledBack', 'RollbackFailed') -notcontains ([string]$restoreStatusProperty.Value)) {
        throw ("Manifest restore status is invalid for '{0}'." -f $Record.Id)
    }

    $expectedRestoreKind = switch ($operation.Kind) {
        'Service'          { 'Service' }
        'TcpAutoTuning'    { 'TcpAutoTuning' }
        'Rss'              { 'Rss' }
        'PowerPerformance' { 'PowerPerformance' }
        'ClientAnimations' { 'ClientAnimations' }
        default            { 'None' }
    }
    if ([string]$Record.RestoreKind -cne $expectedRestoreKind) {
        throw ("Manifest restore kind is invalid for operation '{0}'." -f $Record.Id)
    }
    if (-not $operation.Reversible) {
        return
    }

    Assert-RestoreStateSafe -Kind $expectedRestoreKind -State $Record.BeforeState -Operation $operation -Label 'BeforeState'
    $afterProperty = $Record.PSObject.Properties['AfterState']
    if ([string]$Record.Status -eq 'Succeeded' -and ($null -eq $afterProperty -or $null -eq $afterProperty.Value)) {
        throw ("Manifest is missing the verified post-change state for '{0}'." -f $Record.Id)
    }
    if ($null -ne $afterProperty -and $null -ne $afterProperty.Value) {
        Assert-RestoreStateSafe -Kind $expectedRestoreKind -State $afterProperty.Value -Operation $operation -Label 'AfterState'
    }
    $preRestoreProperty = $Record.PSObject.Properties['PreRestoreState']
    if ($null -ne $restoreStatusProperty -and
        @('Prepared', 'RolledBack', 'RollbackFailed') -contains ([string]$restoreStatusProperty.Value)) {
        if ($null -eq $preRestoreProperty -or $null -eq $preRestoreProperty.Value) {
            throw ("Manifest is missing pre-restore state for interrupted record '{0}'." -f $Record.Id)
        }
        Assert-RestoreStateSafe -Kind $expectedRestoreKind -State $preRestoreProperty.Value -Operation $operation -Label 'PreRestoreState'
    }
    $failureStateProperty = $Record.PSObject.Properties['PostRestoreFailureState']
    if ($null -ne $failureStateProperty -and $null -ne $failureStateProperty.Value) {
        Assert-RestoreStateSafe -Kind $expectedRestoreKind -State $failureStateProperty.Value -Operation $operation -Label 'PostRestoreFailureState'
    }
}

function Save-LoadedRestoreManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)] [string]$Path,
        [switch]$PreservePreviousGeneration
    )

    Write-ManifestEnvelope -Manifest $Manifest -Path $Path -PreservePreviousGeneration:$PreservePreviousGeneration
}

function Set-RestoreRecordStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [ValidateSet('Prepared', 'Succeeded', 'Failed', 'AlreadyRestored', 'RolledBack', 'RollbackFailed')] [string]$Status,
        [Parameter(Mandatory = $true)] [string]$Message
    )

    $Record | Add-Member -NotePropertyName RestoreStatus -NotePropertyValue $Status -Force
    $Record | Add-Member -NotePropertyName RestoreAttemptedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $Record | Add-Member -NotePropertyName RestoreMessage -NotePropertyValue $Message -Force
}

function Prepare-RestoreRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] $PreRestoreState
    )

    $Record | Add-Member -NotePropertyName PreRestoreState -NotePropertyValue $PreRestoreState -Force
    $Record | Add-Member -NotePropertyName RestorePreparedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $Record | Add-Member -NotePropertyName PostRestoreFailureState -NotePropertyValue $null -Force
    Set-RestoreRecordStatus -Record $Record -Status 'Prepared' -Message 'Restore intent and exact pre-restore state were persisted before mutation.'
}

function Invoke-RestoreStateByKind {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Kind,
        [Parameter(Mandatory = $true)] $State
    )

    switch ($Kind) {
        'Service'          { Restore-ServiceState -BeforeState $State }
        'TcpAutoTuning'    { Restore-TcpAutoTuningState -BeforeState $State }
        'Rss'              { Restore-RssState -BeforeState $State }
        'PowerPerformance' { Restore-PowerPerformanceState -BeforeState $State }
        'ClientAnimations' { Restore-ClientAnimationsState -BeforeState $State }
        default            { throw ("Unsupported restore kind '{0}'." -f $Kind) }
    }
}

function Test-RestoreCurrentStateExpected {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] $CurrentState
    )

    $afterStateProperty = $Record.PSObject.Properties['AfterState']
    if ($null -ne $afterStateProperty -and $null -ne $afterStateProperty.Value -and
        (Test-RestoreStateEquivalent -Kind ([string]$Record.RestoreKind) -Left $CurrentState -Right $afterStateProperty.Value)) {
        return $true
    }

    $restoreStatusProperty = $Record.PSObject.Properties['RestoreStatus']
    $preRestoreProperty = $Record.PSObject.Properties['PreRestoreState']
    if ($null -ne $restoreStatusProperty -and
        @('Prepared', 'RolledBack') -contains ([string]$restoreStatusProperty.Value) -and
        $null -ne $preRestoreProperty -and $null -ne $preRestoreProperty.Value -and
        (Test-RestoreStateEquivalent -Kind ([string]$Record.RestoreKind) -Left $CurrentState -Right $preRestoreProperty.Value)) {
        return $true
    }
    return $false
}

function Get-NonOverridableRestoreBlockReason {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Kind,
        [Parameter(Mandatory = $true)] $CurrentState,
        [Parameter(Mandatory = $true)] $SavedState
    )

    if ($Kind -eq 'TcpAutoTuning' -and
        @($CurrentState | Where-Object { [string]$_.AutoTuningLevelEffective -eq 'GroupPolicy' }).Count -gt 0) {
        return 'Restore was refused because at least one target TCP template is now controlled by Group Policy. ForceRestoreDivergedState cannot override policy ownership.'
    }
    if ($Kind -eq 'PowerPerformance' -and
        [string]$CurrentState.Mechanism -cne [string]$SavedState.Mechanism) {
        return 'Restore was refused because the Windows power mechanism changed since Apply, such as after an OS-family upgrade. ForceRestoreDivergedState cannot cross mechanisms safely.'
    }
    if ($Kind -eq 'Service' -and
        -not (Test-ServiceStableMappingEquivalent -Left $CurrentState -Right $SavedState)) {
        return 'Restore was refused because the independently verified service executable, ServiceDll, account, or service type mapping changed since Apply. A replacement service is never reconfigured automatically, even with ForceRestoreDivergedState.'
    }
    return $null
}

function Assert-RestoreManifestSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo,
        [Parameter(Mandatory = $true)] [object[]]$Catalog
    )

    if ([int]$Manifest.SchemaVersion -ne $script:SchemaVersion -or
        [string]$Manifest.ScriptName -cne $script:ScriptName -or
        [string]$Manifest.ScriptVersion -cne $script:ScriptVersion) {
        throw 'Backup manifest schema, script identity, or producer version is not supported by this exact release.'
    }
    if ([string]$Manifest.Machine.DeviceIdentityHash -cne [string]$OsInfo.DeviceIdentityHash) {
        throw 'Rollback manifest device identity does not match this computer.'
    }
    if ([string]$Manifest.Machine.ComputerName -ine [string]$OsInfo.ComputerName -and -not $AllowComputerRename) {
        throw 'Rollback manifest computer name does not match. Use -AllowComputerRename only after verifying this is the same renamed endpoint.'
    }
    if (@($Manifest.Records).Count -gt 1000) {
        throw 'Backup manifest contains more than 1,000 records and was rejected.'
    }
    $recordIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in @($Manifest.Records)) {
        if ([string]::IsNullOrWhiteSpace([string]$record.Id) -or -not $recordIds.Add([string]$record.Id)) {
            throw ("Backup manifest contains an empty or duplicate operation ID '{0}'." -f $record.Id)
        }
        Assert-RestoreRecordSafe -Record $record -Catalog $Catalog
    }
}

function Format-RestoreConsentContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Kind,
        [Parameter(Mandatory = $true)] $CurrentState,
        [Parameter(Mandatory = $true)] $SavedState
    )

    $summary = switch ($Kind) {
        'Service' {
            $fingerprintChanged = -not (Test-ServiceIdentityFingerprintEquivalent -Left $CurrentState -Right $SavedState)
            'Current: startup={0}, state={1}. Saved target: startup={2}, state={3}, delayed-auto={4}. Serviced fingerprint changed={5}. {6}. {7}.' -f
                $CurrentState.StartMode, $CurrentState.State, $SavedState.StartMode, $SavedState.State,
                $SavedState.DelayedAutoStart, $fingerprintChanged,
                (Format-ServiceIdentityEvidence -State $CurrentState -Label 'verified current identity'),
                (Format-ServiceIdentityEvidence -State $SavedState -Label 'saved identity evidence')
        }
        'TcpAutoTuning' {
            $current = @($CurrentState | ForEach-Object { '{0}={1}' -f $_.SettingName, $_.AutoTuningLevelLocal }) -join ', '
            $saved = @($SavedState | ForEach-Object { '{0}={1}' -f $_.SettingName, $_.AutoTuningLevelLocal }) -join ', '
            'Current local levels: {0}. Saved target levels: {1}.' -f $current, $saved
        }
        'Rss' {
            $current = @($CurrentState | ForEach-Object { '{0} [{1}] enabled={2}' -f $_.Name, $_.InterfaceGuid, $_.Enabled }) -join ', '
            $saved = @($SavedState | ForEach-Object { '{0} [{1}] enabled={2}' -f $_.Name, $_.InterfaceGuid, $_.Enabled }) -join ', '
            'Current RSS: {0}. Saved target RSS: {1}.' -f $current, $saved
        }
        'PowerPerformance' {
            'Current: {0}={1}. Saved target: {2}={3}.' -f
                $CurrentState.Mechanism, $CurrentState.Guid, $SavedState.Mechanism, $SavedState.Guid
        }
        'ClientAnimations' {
            'Current client-area animations enabled={0}. Saved target enabled={1}.' -f $CurrentState.Enabled, $SavedState.Enabled
        }
        default { 'The current state will be replaced with the authenticated saved state.' }
    }
    if ($summary.Length -gt 2000) {
        return $summary.Substring(0, 2000) + ' [summary truncated]'
    }
    return $summary
}

function Invoke-RestoreManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo,
        [Parameter(Mandatory = $true)] [object[]]$Catalog
    )

    $resolvedPath = Assert-SafeOperationalFilePath -Path $Path -Purpose 'Restore BackupPath'
    $protectedDataRoot = Get-DefaultDataRoot
    Assert-PathWithinDataRoot -Path $resolvedPath -DataRoot $protectedDataRoot -Purpose 'rollback manifest'
    $previousPath = '{0}.previous' -f $resolvedPath
    [void](Assert-SafeOperationalFilePath -Path $previousPath -Purpose 'Previous rollback-manifest path')
    Assert-PathWithinDataRoot -Path $previousPath -DataRoot $protectedDataRoot -Purpose 'previous rollback-manifest generation'
    if (Test-Path -LiteralPath $resolvedPath) {
        if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf) -or
            (Test-PathContainsReparsePoint -Path $resolvedPath)) {
            throw 'The primary rollback-manifest target exists but is not a regular, non-reparse file; restore was refused before mutation.'
        }
    }
    $manifest = $null
    $loadedManifestPath = $null
    $candidateErrors = New-Object System.Collections.ArrayList
    foreach ($candidatePath in @($resolvedPath, $previousPath)) {
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            [void]$candidateErrors.Add(("{0}: not found" -f (Split-Path -Leaf $candidatePath)))
            continue
        }

        try {
            if (Test-PathContainsReparsePoint -Path $candidatePath) {
                throw 'the file or one of its parent folders is a reparse point'
            }
            if ((Get-DriveTypeForPath -Path $candidatePath) -ne [IO.DriveType]::Fixed) {
                throw 'the file is not on a local fixed drive'
            }
            $manifestFile = Get-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
            if ($manifestFile.Length -gt 10MB) {
                throw 'the file exceeds the 10 MB safety limit'
            }
            Assert-ExistingRestrictedFileAcl -Path $candidatePath
            $candidateManifest = Read-ManifestEnvelope -Path $candidatePath
            Assert-RestoreManifestSafe -Manifest $candidateManifest -OsInfo $OsInfo -Catalog $Catalog
            $manifest = $candidateManifest
            $loadedManifestPath = $candidatePath
            break
        }
        catch {
            [void]$candidateErrors.Add(("{0}: {1}" -f (Split-Path -Leaf $candidatePath), $_.Exception.Message))
        }
    }
    if ($null -eq $manifest) {
        throw ("No valid authenticated rollback-manifest generation is available. {0}" -f ($candidateErrors -join '; '))
    }
    if ($loadedManifestPath -cne $resolvedPath) {
        Write-Log -Level 'WARN' -Message 'The primary rollback manifest was unavailable or invalid; the authenticated previous generation was recovered.'
    }
    $preservePreviousGeneration = $loadedManifestPath -cne $resolvedPath

    if ([string]$manifest.Machine.ComputerName -ine $OsInfo.ComputerName) {
        Write-Log -Level 'WARN' -Message 'The computer name changed since Apply; -AllowComputerRename was supplied and stable device identity matched.'
    }
    $manifestUserMatches = [string]$manifest.Machine.UserSid -ceq [string]$OsInfo.CurrentUserSid
    if (-not $manifestUserMatches) {
        Write-Log -Level 'WARN' -Message 'Restore is running as a different user. Machine-scoped records may continue; user-scoped records will be blocked.'
    }
    $records = @($manifest.Records | Where-Object {
        $restoreStatusProperty = $_.PSObject.Properties['RestoreStatus']
        $alreadyCompleted = $null -ne $restoreStatusProperty -and @('Succeeded', 'AlreadyRestored') -contains ([string]$restoreStatusProperty.Value)
        $_.Reversible -eq $true -and @('Prepared', 'Succeeded', 'RollbackFailed') -contains ([string]$_.Status) -and -not $alreadyCompleted
    })
    if ($null -ne $RestoreOptimization -and @($RestoreOptimization).Count -gt 0) {
        foreach ($requestedRestoreId in $RestoreOptimization) {
            $catalogMatch = @($Catalog | Where-Object { $_.Id -ieq $requestedRestoreId -and $_.Reversible })
            if ($catalogMatch.Count -ne 1) {
                throw ("Restore operation ID '{0}' is unknown or not reversible." -f $requestedRestoreId)
            }
            if (@($manifest.Records | Where-Object { $_.Id -ieq $requestedRestoreId }).Count -eq 0) {
                throw ("Restore operation ID '{0}' is not present in this manifest." -f $requestedRestoreId)
            }
        }
        $records = @($records | Where-Object { $RestoreOptimization -icontains $_.Id })
    }
    [array]::Reverse($records)

    if ($records.Count -eq 0) {
        Write-Log -Level 'INFO' -Message 'The manifest has no pending reversible records.'
        return
    }

    for ($index = 0; $index -lt $records.Count; $index++) {
        $record = $records[$index]
        $restoreJournaled = $false
        $preRestoreState = $null
        $stateShownForConsent = $null
        $percent = [int](($index / [math]::Max(1, $records.Count)) * 100)
        Write-Progress -Id 1 -Activity 'Restoring WinOptimize changes' -Status ([string]$record.Id) -PercentComplete $percent
        try {
            $restoreKind = [string]$record.RestoreKind
            $operation = @($Catalog | Where-Object { $_.Id -ieq ([string]$record.Id) })
            if ($operation.Count -ne 1) {
                throw ("Restore operation '{0}' no longer resolves uniquely in the catalog." -f $record.Id)
            }
            $operation = $operation[0]
            if ($ConsentPolicy -eq 'NoToAll' -or
                ($ConsentPolicy -eq 'Recommended' -and -not $operation.Recommended)) {
                [void](Request-OperationConsent -Operation $operation -Purpose Restore)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Skipped' -Message 'Restore declined by consent policy before state discovery.')
                continue
            }
            $isUserScopedRecord = $restoreKind -eq 'ClientAnimations' -or $restoreKind -eq 'PowerPerformance'
            if ($isUserScopedRecord -and
                (-not $manifestUserMatches -or -not (Test-IsInteractiveUserContext -UserSid ([string]$OsInfo.CurrentUserSid)))) {
                $message = 'This record is user-scoped and belongs to the user who ran Apply; it was not restored in the current user context.'
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }

            $currentState = Get-CurrentStateForRestoreRecord -Record $record -OsInfo $OsInfo
            $nonOverridableReason = Get-NonOverridableRestoreBlockReason -Kind $restoreKind -CurrentState $currentState -SavedState $record.BeforeState
            if ($null -ne $nonOverridableReason) {
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $nonOverridableReason)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $nonOverridableReason)
                Set-PartialExitCode
                continue
            }
            if (Test-RestoreStateEquivalent -Kind $restoreKind -Left $currentState -Right $record.BeforeState) {
                $message = 'Current state already matches the saved original state.'
                if (-not $script:IsWhatIf) {
                    Set-RestoreRecordStatus -Record $record -Status 'AlreadyRestored' -Message $message
                    Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
                }
                Write-Log -Level 'INFO' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'AlreadyRestored' -Message $message)
                continue
            }

            $stateMatchesExpected = Test-RestoreCurrentStateExpected -Record $record -CurrentState $currentState
            if (([string]$record.Status -eq 'Prepared' -or -not $stateMatchesExpected) -and -not $ForceRestoreDivergedState) {
                $script:ExitCode = 1
                $message = 'Current state is ambiguous or changed since optimization; restore was blocked. Inspect it, then use -ForceRestoreDivergedState only if overwriting the newer state is intended.'
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Diverged' -Message $message)
                if ($StopOnError) { break }
                continue
            }
            if (-not $script:IsWhatIf -and $restoreKind -eq 'Service' -and
                -not (Test-ServiceIdentityFingerprintEquivalent -Left $currentState -Right $record.BeforeState) -and
                -not $AcknowledgeServicedServiceIdentityDrift) {
                $message = 'The service mapping is still trusted, but its signed file fingerprint changed since Apply. Inspect the full current/saved evidence and use -AcknowledgeServicedServiceIdentityDrift only when authorized.'
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }
            $stateShownForConsent = $currentState
            $restoreContext = Format-RestoreConsentContext -Kind $restoreKind -CurrentState $currentState -SavedState $record.BeforeState
            if (-not (Request-OperationConsent -Operation $operation -AdditionalContext $restoreContext -Purpose Restore)) {
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Skipped' -Message 'Restore declined by consent policy.')
                continue
            }
            if ($ForceRestoreDivergedState -and -not $stateMatchesExpected) {
                Write-Log -Level 'WARN' -Message ("Force-restoring diverged state for {0}." -f $record.Id)
            }

            if (-not $script:IsWhatIf -and $restoreKind -eq 'PowerPerformance' -and
                [string]$record.BeforeState.Mechanism -eq 'Windows10PowerPlan') {
                $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
                if ($null -ne $powerPlanBlock) {
                    [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $powerPlanBlock)
                    Set-PartialExitCode
                    continue
                }
            }

            $isRemoteNetworkRestore = @('Rss', 'TcpAutoTuning') -contains $restoreKind -and (Test-IsRemoteSession)
            if ($isRemoteNetworkRestore -and -not $script:IsWhatIf -and -not $AllowNetworkChangeInRemoteSession) {
                $message = 'Network restore is blocked in a remote session. Use -AllowNetworkChangeInRemoteSession only if an interruption is acceptable.'
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }
            if (-not $script:IsWhatIf -and
                (@('Rss', 'TcpAutoTuning') -contains $restoreKind) -and
                -not $AcknowledgeNetworkInterruption) {
                $message = 'Network restore requires -AcknowledgeNetworkInterruption because active connectivity may be affected.'
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }

            if (-not (Test-ShouldProcessOperation -Target ([string]$record.Id) -Action 'Restore saved state')) {
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'WhatIf' -Message 'State was not restored.')
                continue
            }
            if ($restoreKind -eq 'PowerPerformance' -and
                [string]$record.BeforeState.Mechanism -eq 'Windows10PowerPlan') {
                $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
                if ($null -ne $powerPlanBlock) {
                    [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $powerPlanBlock)
                    Set-PartialExitCode
                    continue
                }
            }

            # -Confirm can pause for an arbitrary time. Re-read after it and
            # repeat the complete drift decision immediately before journaling.
            $currentState = Get-CurrentStateForRestoreRecord -Record $record -OsInfo $OsInfo
            if ($restoreKind -eq 'Service' -and
                -not (Test-ServiceIdentityFingerprintEquivalent -Left $currentState -Right $stateShownForConsent)) {
                $message = 'The verified service file fingerprint changed after consent; restore was refused. Review the new identity and run again.'
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }
            $nonOverridableReason = Get-NonOverridableRestoreBlockReason -Kind $restoreKind -CurrentState $currentState -SavedState $record.BeforeState
            if ($null -ne $nonOverridableReason) {
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $nonOverridableReason)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $nonOverridableReason)
                Set-PartialExitCode
                continue
            }
            if (Test-RestoreStateEquivalent -Kind $restoreKind -Left $currentState -Right $record.BeforeState) {
                $message = 'Current state reached the saved original state while confirmation was pending.'
                Set-RestoreRecordStatus -Record $record -Status 'AlreadyRestored' -Message $message
                Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
                Write-Log -Level 'INFO' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'AlreadyRestored' -Message $message)
                continue
            }
            $stateMatchesExpected = Test-RestoreCurrentStateExpected -Record $record -CurrentState $currentState
            if (([string]$record.Status -eq 'Prepared' -or -not $stateMatchesExpected) -and -not $ForceRestoreDivergedState) {
                $script:ExitCode = 1
                $message = 'State changed while confirmation was pending; restore was blocked. Inspect it and run again.'
                Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Diverged' -Message $message)
                if ($StopOnError) { break }
                continue
            }
            if ($restoreKind -eq 'Service' -and
                -not (Test-ServiceIdentityFingerprintEquivalent -Left $currentState -Right $record.BeforeState) -and
                -not $AcknowledgeServicedServiceIdentityDrift) {
                $message = 'The service fingerprint no longer matches the saved evidence and the required servicing-drift acknowledgement was not supplied.'
                [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                Set-PartialExitCode
                continue
            }

            $preRestoreState = $currentState
            Assert-RestoreStateSafe -Kind $restoreKind -State $preRestoreState -Operation $operation -Label 'PreRestoreState'
            Prepare-RestoreRecord -Record $record -PreRestoreState $preRestoreState
            Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
            $restoreJournaled = $true

            if ($restoreKind -eq 'PowerPerformance' -and
                [string]$record.BeforeState.Mechanism -eq 'Windows10PowerPlan') {
                # Recheck after the journal write, immediately before the
                # restore mutation. An unplug event must fail closed.
                $powerPlanBlock = Get-Windows10PowerPlanBlockMessage
                if ($null -ne $powerPlanBlock) {
                    $message = '{0} No restore mutation was attempted.' -f $powerPlanBlock
                    Set-RestoreRecordStatus -Record $record -Status 'Failed' -Message $message
                    Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
                    $restoreJournaled = $false
                    Write-Log -Level 'WARN' -Message ("{0}: {1}" -f $record.Id, $message)
                    [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Blocked' -Message $message)
                    Set-PartialExitCode
                    continue
                }
            }

            Invoke-RestoreStateByKind -Kind $restoreKind -State $record.BeforeState

            $verifiedState = Get-CurrentStateForRestoreRecord -Record $record -OsInfo $OsInfo
            if (-not (Test-RestoreStateEquivalent -Kind $restoreKind -Left $verifiedState -Right $record.BeforeState) -or
                ($restoreKind -eq 'Service' -and
                 -not (Test-ServiceIdentityFingerprintEquivalent -Left $verifiedState -Right $preRestoreState))) {
                throw 'Post-restore verification did not match the saved original state.'
            }

            $message = 'Saved original state was restored and verified.'
            Set-RestoreRecordStatus -Record $record -Status 'Succeeded' -Message $message
            Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
            Write-Log -Level 'SUCCESS' -Message ("{0}: {1}" -f $record.Id, $message)
            [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status 'Restored' -Message $message)
        }
        catch {
            $script:ExitCode = 1
            $primaryRestoreRecord = $_
            $primaryRestoreError = $primaryRestoreRecord.Exception.Message
            $primaryRestoreDetail = Format-ErrorRecordForLog -ErrorRecord $primaryRestoreRecord
            $message = $primaryRestoreError
            $resultStatus = 'Failed'
            if (-not $script:IsWhatIf -and $restoreJournaled) {
                try {
                    Invoke-RestoreStateByKind -Kind ([string]$record.RestoreKind) -State $preRestoreState
                    $rollbackObserved = Get-CurrentStateForRestoreRecord -Record $record -OsInfo $OsInfo
                    if (-not (Test-RestoreStateEquivalent -Kind ([string]$record.RestoreKind) -Left $rollbackObserved -Right $preRestoreState) -or
                        ([string]$record.RestoreKind -eq 'Service' -and
                         -not (Test-ServiceIdentityFingerprintEquivalent -Left $rollbackObserved -Right $preRestoreState))) {
                        throw 'Pre-restore state rollback verification failed.'
                    }
                    $message = '{0} The exact pre-restore state was reinstated and verified.' -f $primaryRestoreError
                    $resultStatus = 'RestoreRolledBack'
                    Set-RestoreRecordStatus -Record $record -Status 'RolledBack' -Message $message
                    Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
                }
                catch {
                    $rollbackError = $_.Exception.Message
                    $failureObserved = $null
                    try { $failureObserved = Get-CurrentStateForRestoreRecord -Record $record -OsInfo $OsInfo } catch { }
                    $record | Add-Member -NotePropertyName PostRestoreFailureState -NotePropertyValue $failureObserved -Force
                    $message = '{0} Automatic rollback to the pre-restore state failed or could not be verified: {1}' -f $primaryRestoreError, $rollbackError
                    $resultStatus = 'RestoreRollbackFailed'
                    try {
                        Set-RestoreRecordStatus -Record $record -Status 'RollbackFailed' -Message $message
                        Save-LoadedRestoreManifest -Manifest $manifest -Path $resolvedPath -PreservePreviousGeneration:$preservePreviousGeneration
                    }
                    catch {
                        $message = '{0} Restore failure status could not be persisted: {1}' -f $message, $_.Exception.Message
                    }
                }
            }
            Write-Log -Level 'ERROR' -Message ("Restore failed for {0}: {1}; primaryDetail={2}" -f $record.Id, $message, $primaryRestoreDetail)
            [void](Add-Result -Id ([string]$record.Id) -Category ([string]$record.Category) -Status $resultStatus -Message $message)
            if ($StopOnError) {
                $script:OperationFailureEscalated = $true
                throw
            }
        }
    }

    Write-Progress -Id 1 -Activity 'Restoring WinOptimize changes' -Completed
}

function Show-ResultSummary {
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-UiHost -Message 'WinOptimize result summary' -Color Cyan
    Write-UiHost -Message '--------------------------' -Color Cyan
    if ($script:Results.Count -eq 0) {
        Write-Host 'No operations were run.'
        return
    }

    $table = $script:Results | Select-Object Id, Status, Message | Format-Table -AutoSize -Wrap | Out-String -Width 220
    Write-Host $table
}

function Invoke-Preflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$OsInfo,
        [switch]$ReadOnlyListing
    )

    if ($env:OS -ne 'Windows_NT') {
        throw 'This script supports Windows client only.'
    }
    if ($OsInfo.ProductType -ne 1 -or @('Windows 10', 'Windows 11') -notcontains $OsInfo.Family) {
        throw ("Unsupported operating system: {0}. Windows 10/11 client is required." -f $OsInfo.Caption)
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and
        (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess)) {
        throw 'Apply and Restore require a 64-bit Windows operating system and 64-bit Windows PowerShell.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and -not $OsInfo.DeviceIdentityReliable) {
        throw 'Apply/Restore requires valid, non-default MachineGuid and SMBIOS UUID identity material so rollback data cannot be bound ambiguously.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and -not (Test-IsAdministrator)) {
        throw ("{0} mode requires an elevated Windows PowerShell session (Run as administrator)." -f $Mode)
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and $ConsentPolicy -eq 'Ask' -and
        -not $script:IsWhatIf -and -not (Test-IsInteractiveUserContext -UserSid ([string]$OsInfo.CurrentUserSid))) {
        throw 'Interactive consent requires a signed-in interactive user session. Use an explicit noninteractive consent policy from an approved execution context.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and
        ($OsInfo.IsManagedDevice -or -not $OsInfo.ManagementDetectionReliable) -and -not $AllowManagedDevice) {
        if ($OsInfo.IsManagedDevice) {
            throw ("This computer has management signals ({0}). Coordinate with IT/change control, then use -AllowManagedDevice only after approval." -f ($OsInfo.ManagementSignals -join ', '))
        }
        throw 'Device-management detection was incomplete. Apply/Restore fails closed; use -AllowManagedDevice only after confirming change control.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and
        $NonInteractive -and $ConsentPolicy -eq 'Ask' -and -not $script:IsWhatIf) {
        throw 'NonInteractive Apply/Restore mode requires -ConsentPolicy Recommended, YesToAll, or NoToAll.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and $NonInteractive -and
        $script:ScriptBoundParameters.ContainsKey('Confirm') -and
        [bool]$script:ScriptBoundParameters['Confirm']) {
        throw '-NonInteractive cannot be combined with the common -Confirm switch.'
    }
    if (-not $ReadOnlyListing -and @('Apply', 'Restore') -contains $Mode -and $NonInteractive -and -not $script:IsWhatIf -and
        [string]$ConfirmPreference -eq 'Low' -and
        -not ($script:ScriptBoundParameters.ContainsKey('Confirm') -and -not [bool]$script:ScriptBoundParameters['Confirm'])) {
        throw '-NonInteractive cannot run while the ambient ConfirmPreference is Low because ShouldProcess would prompt. Use -Confirm:$false or restore ConfirmPreference to High.'
    }
    if (-not $ReadOnlyListing -and $IncludeStartupCommandLines -and -not $IncludeSensitiveAuditData) {
        throw '-IncludeStartupCommandLines requires -IncludeSensitiveAuditData because startup commands can contain secrets or sensitive paths.'
    }
    if (-not $ReadOnlyListing -and $Mode -ne 'Audit' -and
        ($IncludeStartupCommandLines -or $IncludeSensitiveAuditData -or -not [string]::IsNullOrWhiteSpace($ReportPath))) {
        throw 'ReportPath and sensitive/startup audit switches are valid only with -Mode Audit.'
    }
    if (-not $ReadOnlyListing -and $Mode -eq 'Restore' -and [string]::IsNullOrWhiteSpace($BackupPath)) {
        throw 'Restore mode requires -BackupPath.'
    }
    if (-not $ReadOnlyListing -and $Mode -eq 'Restore' -and $ConsentPolicy -eq 'Recommended') {
        throw 'ConsentPolicy Recommended is Apply-specific and is not valid for Restore. Use Ask, YesToAll, or NoToAll.'
    }
    if (-not $ReadOnlyListing -and $Mode -eq 'Restore') {
        $hasApplySelector = ($null -ne $Category -and @($Category).Count -gt 0) -or
            ($null -ne $IncludeOptimization -and @($IncludeOptimization).Count -gt 0) -or
            ($null -ne $ExcludeOptimization -and @($ExcludeOptimization).Count -gt 0) -or
            ($null -ne $ServiceName -and @($ServiceName).Count -gt 0) -or
            ($null -ne $AdapterInterfaceGuid -and @($AdapterInterfaceGuid).Count -gt 0) -or
            ($null -ne $VolumeDriveLetter -and @($VolumeDriveLetter).Count -gt 0) -or
            $AllRecommended -or $CleanUserTemp -or $CleanWindowsTemp -or
            $ClearDeliveryOptimizationCache -or $RunComponentCleanup -or $OptimizeFixedVolumes -or
            $NormalizeTcpAutoTuning -or $EnableReceiveSideScaling -or $SetBestPerformancePowerMode -or
            $DisableClientAnimations -or $ReviewStartupApps -or $ReviewStorageSense -or
            $DisableOptionalServices -or $DisableDemandStartServices
        if ($hasApplySelector) {
            throw 'Apply selectors are invalid in Restore mode. Use -RestoreOptimization with exact operation IDs.'
        }
    }
    if (-not $ReadOnlyListing -and $Mode -ne 'Restore' -and $null -ne $RestoreOptimization -and @($RestoreOptimization).Count -gt 0) {
        throw '-RestoreOptimization is valid only with -Mode Restore.'
    }
    if (-not $ReadOnlyListing -and $ForceRestoreDivergedState -and $Mode -ne 'Restore') {
        throw '-ForceRestoreDivergedState is valid only with -Mode Restore.'
    }
    if (-not $ReadOnlyListing -and $AllowComputerRename -and $Mode -ne 'Restore') {
        throw '-AllowComputerRename is valid only with -Mode Restore.'
    }

    if ($OsInfo.Family -eq 'Windows 10') {
        Write-Log -Level 'WARN' -Message 'Windows 10 standard support ended on 2025-10-14. Verify LTSC/ESU coverage or upgrade to Windows 11; optimization is not a security substitute.'
    }
    if ($OsInfo.IsManagedDevice -or -not $OsInfo.ManagementDetectionReliable) {
        Write-Log -Level 'WARN' -Message ("Management signals='{0}'; detection reliable={1}. Policy may override local settings." -f ($OsInfo.ManagementSignals -join ', '), $OsInfo.ManagementDetectionReliable)
    }
}

function Invoke-WinOptimizeMain {
    [CmdletBinding()]
    param()

$fatalError = $null
try {
    & ${function:Initialize-TrustedCommandEnvironment}
    Enter-SingleInstance
    Initialize-Logging
    Write-Log -Level 'INFO' -Message ("Starting {0} {1}. Mode={2}; WhatIf={3}" -f $script:ScriptName, $script:ScriptVersion, $Mode, $script:IsWhatIf)

    if ($env:OS -ne 'Windows_NT') {
        throw 'This script supports Windows client only.'
    }

    $osInfo = Get-OperatingSystemInfo
    Invoke-Preflight -OsInfo $osInfo -ReadOnlyListing:$ListOptimizations
    Write-Log -Level 'INFO' -Message ("Detected {0}; version {1}; build {2}; architecture {3}." -f $osInfo.Caption, $osInfo.Version, $osInfo.BuildNumber, $osInfo.OSArchitecture)

    $catalog = @(Get-OptimizationCatalog)

    if ($ListOptimizations) {
        $list = @($catalog | ForEach-Object {
            $availability = Get-OperationAvailability -Operation $_ -OsInfo $osInfo
            [pscustomobject][ordered]@{
                Id          = $_.Id
                Category    = $_.Category
                Risk        = $_.Risk
                Recommended = $_.Recommended
                Reversible  = $_.Reversible
                BulkEligible = $_.BulkEligible
                ServiceName = $_.ServiceName
                Kind        = $_.Kind
                Available   = $availability.Available
                AvailabilityReason = $availability.Reason
                DisplayName = $_.DisplayName
                Description = $_.Description
                Impact      = $_.Impact
            }
        })
        $formatted = $list | Format-Table -AutoSize -Wrap | Out-String -Width 240
        Write-Host $formatted
        Write-Log -Level 'SUCCESS' -Message 'Optimization catalog listed.'
        if ($PassThru) { Write-Output $list }
    }
    elseif ($Mode -eq 'Audit') {
        $selected = @(Get-SelectedOperations -Catalog $catalog)
        $snapshot = Get-AuditSnapshot -OsInfo $osInfo -Catalog $selected
        $savedReport = Write-AuditReport -Snapshot $snapshot
        [void](Add-Result -Id 'audit.system' -Category 'Audit' -Status $snapshot.AuditStatus -Message ("Audit report saved to {0}" -f $savedReport))

        Write-Host ''
        Write-Host ("Operating system: {0} (build {1})" -f $osInfo.Caption, $osInfo.BuildNumber)
        Write-Host ("Physical memory: {0}" -f (Format-ByteSize -Bytes $osInfo.TotalMemoryBytes))
        if (@($selected | Where-Object { $_.Category -eq 'Startup' }).Count -gt 0) {
            Write-Host ("Startup entries found: {0:N0}" -f @($snapshot.StartupApplications).Count)
        }
        $systemVolume = @($snapshot.Volumes | Where-Object { $_.DriveLetter -eq $env:SystemDrive.TrimEnd(':') })
        if ($systemVolume.Count -gt 0) {
            Write-Host ("System drive free: {0} ({1:N2}%)" -f (Format-ByteSize -Bytes $systemVolume[0].FreeBytes), $systemVolume[0].FreePercent)
        }
        $auditLogLevel = if ($snapshot.AuditStatus -eq 'Complete') { 'SUCCESS' } else { 'WARN' }
        Write-Log -Level $auditLogLevel -Message ("Audit status={0}. Report={1}" -f $snapshot.AuditStatus, $savedReport)
        Show-ResultSummary
        Write-UiHost -Message ("Log: {0}" -f $script:LogPath)
        if ($PassThru) { Write-Output $snapshot }
    }
    elseif ($Mode -eq 'Restore') {
        Invoke-RestoreManifest -Path $BackupPath -OsInfo $osInfo -Catalog $catalog
        Show-ResultSummary
        Write-Host ("Log: {0}" -f $script:LogPath)
        if ($PassThru) { Write-Output @($script:Results) }
    }
    else {
        $selected = @(Get-SelectedOperations -Catalog $catalog)
        if ($selected.Count -eq 0) {
            throw 'No operations remain after selection and exclusions.'
        }

        if ($script:IsWhatIf) {
            Write-Log -Level 'INFO' -Message 'WhatIf mode: no rollback key or manifest will be created because no selected operation may mutate Windows.'
        }
        else {
            Initialize-SessionManifest -OsInfo $osInfo
            Write-Log -Level 'INFO' -Message ("Rollback manifest initialized: {0}" -f $script:BackupPath)
            Write-Host ("Rollback manifest: {0}" -f $script:BackupPath)
        }

        for ($index = 0; $index -lt $selected.Count; $index++) {
            $operation = $selected[$index]
            $percent = [int](($index / [math]::Max(1, $selected.Count)) * 100)
            Write-Progress -Id 1 -Activity 'Applying selected Windows optimizations' -Status $operation.DisplayName -PercentComplete $percent
            Write-Log -Level 'INFO' -Message ("Evaluating {0}: {1}" -f $operation.Id, $operation.DisplayName)

            if ($ConsentPolicy -eq 'NoToAll' -or
                ($ConsentPolicy -eq 'Recommended' -and -not $operation.Recommended)) {
                [void](Request-OperationConsent -Operation $operation)
                [void](Add-Result -Id $operation.Id -Category $operation.Category -Status 'Skipped' -Message 'Declined by consent policy before operational discovery.')
                continue
            }

            $availability = Get-OperationAvailability -Operation $operation -OsInfo $osInfo
            if (-not $availability.Available) {
                $message = [string]$availability.Reason
                Write-Log -Level 'WARN' -Message ("{0} unavailable: {1}" -f $operation.Id, $message)
                [void](Add-Result -Id $operation.Id -Category $operation.Category -Status 'Unavailable' -Message $message)
                Set-PartialExitCode
                continue
            }

            try {
                $operationResult = Invoke-Operation -Operation $operation -OsInfo $osInfo
                if (@('Blocked', 'Unavailable') -contains [string]$operationResult.Status) {
                    Set-PartialExitCode
                }
            }
            catch {
                $script:ExitCode = 1
                $operationError = $_
                $message = $operationError.Exception.Message
                $detail = Format-ErrorRecordForLog -ErrorRecord $operationError
                Write-Log -Level 'ERROR' -Message ("{0} failed: {1}" -f $operation.Id, $detail)
                [void](Add-Result -Id $operation.Id -Category $operation.Category -Status 'Failed' -Message $message)
                if ($StopOnError) {
                    $script:OperationFailureEscalated = $true
                    throw
                }
            }
        }

        Write-Progress -Id 1 -Activity 'Applying selected Windows optimizations' -Completed
        if ($null -ne $script:Session) {
            $script:Session.Outcome = if ($script:ExitCode -eq 0) { 'Completed' } else { 'CompletedWithIssues' }
            $script:Session.CompletedUtc = [DateTime]::UtcNow.ToString('o')
            Save-SessionManifest
        }

        Show-ResultSummary
        if ($null -ne $script:Session) {
            Write-Host ("Rollback manifest: {0}" -f $script:BackupPath)
        }
        Write-Host ("Log: {0}" -f $script:LogPath)
        Write-Host 'No reboot was forced. Review the summary; restart Windows only if an affected application requires it.'
        if ($PassThru) { Write-Output @($script:Results) }
    }
}
catch {
    $fatalRecord = $_
    $fatalError = $fatalRecord.Exception.Message
    # The trusted-command bootstrap can itself fail because a hostile or stale
    # profile alias collides with a private function name. Use Function: calls
    # throughout this rejection path so that the conflicting alias cannot run.
    $fatalDetail = & ${function:Format-ErrorRecordForLog} -ErrorRecord $fatalRecord
    $script:ExitCode = if ($script:OperationFailureEscalated) { 1 } else { 2 }
    if ($null -ne $script:Session) {
        try {
            $script:Session.Outcome = 'Failed'
            $script:Session.CompletedUtc = [DateTime]::UtcNow.ToString('o')
            & ${function:Save-SessionManifest}
        }
        catch {
            # Preserve the original fatal error. An earlier authenticated
            # generation remains the recovery source if this save also fails.
        }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:LogPath)) {
        try {
            & ${function:Write-Log} -Level 'ERROR' -Message ("Fatal error: {0}" -f $fatalDetail)
        }
        catch {
            & ${function:Write-UiHost} -Message '[ERROR] Fatal error logging also failed.' -Color Red
        }
        & ${function:Write-UiHost} -Message ("Log: {0}" -f $script:LogPath)
    }
    else {
        & ${function:Write-UiHost} -Message ("[ERROR] {0}" -f $fatalError) -Color Red
    }
}
finally {
    Microsoft.PowerShell.Utility\Write-Progress -Id 1 -Activity 'WinOptimize' -Completed -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Utility\Write-Progress -Id 2 -Activity 'WinOptimize detail' -Completed -ErrorAction SilentlyContinue
    & ${function:Exit-SingleInstance}
    $env:PSModulePath = $script:OriginalPSModulePath
}

if ($null -ne $fatalError) {
    Microsoft.PowerShell.Utility\Write-Error -Message $fatalError -ErrorAction Continue
}
}

if ($MyInvocation.InvocationName -ne '.') {
    & ${function:Invoke-WinOptimizeMain}
    exit $script:ExitCode
}
