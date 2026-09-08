# WinOptimize 1.0.0

WinOptimize is a conservative, auditable Windows 10/11 performance and maintenance script for 64-bit Windows PowerShell 5.1. It defaults to read-only Audit mode. Apply changes only the operations you select, uses Y/N/A consent, reports progress, verifies post-state, and journals reversible changes to an authenticated rollback manifest.

No generic script can guarantee that a PC will become faster. The useful actions depend on the bottleneck. Microsoft’s own guidance emphasizes updates, restart state, free disk space, startup load, malware checks, visual effects, and power policy; this project automates only the supported subset that can be bounded safely.

## Package contents

- `Invoke-WindowsOptimization.ps1` — the tool.
- `Tests/WinOptimize.Tests.ps1` — Pester 5 static, semantic, consent, and disposable native-file tests.
- `report-source.md` — first-party Microsoft research and the claim-to-source ledger.
- `SHA256SUMS.txt` — package file hashes.

The supplied source is intentionally unsigned and is therefore not a production-deployment artifact for a managed or regulated environment. Review it, validate it on your supported Windows images, then sign and timestamp the frozen `.ps1` with your organization’s trusted code-signing certificate. Because Authenticode changes the script bytes, regenerate `SHA256SUMS.txt` and rebuild/verify the ZIP after signing.

## Supported environment

- Windows 10 or Windows 11 client, not Windows Server.
- 64-bit Windows and 64-bit Windows PowerShell 5.1 Desktop for Apply/Restore.
- An elevated, interactive console for prompted Apply/Restore.
- The elevated token must belong to the current interactive session owner; over-the-shoulder elevation with another administrator account is refused for user-scoped actions.
- A clean `-NoProfile` process. The script detects aliases that collide with private functions and fails closed.
- Managed endpoints require approved change control and the explicit `-AllowManagedDevice` switch.

Windows 10 Home/Pro standard support ended on 14 October 2025. Compatibility with this script does not replace Windows 11 migration, LTSC lifecycle management, or verified ESU enrollment.

## Safe starting workflow

Run these commands from the extracted package directory:

```powershell
# 1. Confirm the script hash against SHA256SUMS.txt.
Get-FileHash .\Invoke-WindowsOptimization.ps1 -Algorithm SHA256

# 2. Review every operation and its live availability.
powershell.exe -NoLogo -NoProfile -File .\Invoke-WindowsOptimization.ps1 -ListOptimizations

# 3. Create a protected, read-only audit report.
powershell.exe -NoLogo -NoProfile -File .\Invoke-WindowsOptimization.ps1 -Mode Audit

# 4. Preview one exact change without mutating Windows.
powershell.exe -NoLogo -NoProfile -File .\Invoke-WindowsOptimization.ps1 `
  -Mode Apply -IncludeOptimization cleanup.user-temp -WhatIf

# 5. Apply only the reviewed action. This prompts once for the folder.
powershell.exe -NoLogo -NoProfile -File .\Invoke-WindowsOptimization.ps1 `
  -Mode Apply -CleanUserTemp
```

Do not copy a manifest without its companion key under the protected WinOptimize data root. Retain the exact signed 1.0.0 script used to create it; this release deliberately accepts rollback manifests only from the same producer version.

## Consent behavior

With the default `-ConsentPolicy Ask`, every applicable operation displays its risk, consequence, and current target state:

- `Y` — approve this operation.
- `N` — decline this operation.
- `A` — approve remaining operations only in the same category and at the same risk level.

For temporary cleanup, one decision covers one resolved folder. Files are never prompted individually. Every folder is preserved; only eligible regular files at least seven days old are considered. Locked/recent files and reparse points are skipped.

`-ConsentPolicy Recommended`, `YesToAll`, and `NoToAll` are explicit automation policies. Unattended irreversible work requires `-AcknowledgeIrreversibleActions`; network work requires `-AcknowledgeNetworkInterruption`. `A` and `YesToAll` never bypass critical-service, policy, identity, path, remote-session, power-source, or maintenance-state safety gates.

## Operations

| Operation ID | Switch | Behavior |
|---|---|---|
| `cleanup.user-temp` | `-CleanUserTemp` | Deletes only aged regular files under the signed-in user’s canonical LocalAppData Temp root; preserves all folders. This is the only Recommended operation in 1.0.0. |
| `cleanup.windows-temp` | `-CleanWindowsTemp` | Separately confirms the canonical Windows Temp root; same handle-based age/reparse rules. |
| `storage.clear-delivery-optimization-cache` | `-ClearDeliveryOptimizationCache` | Uses Microsoft’s supported cmdlet; unpinned cache only. Content may be downloaded again. |
| `storage.component-store-cleanup` | `-RunComponentCleanup` | Runs AnalyzeComponentStore, then StartComponentCleanup. `/ResetBase` is never used. Requires safe servicing state and stable AC power on battery-equipped devices. |
| `storage.optimize-fixed-volumes` | `-OptimizeFixedVolumes` | Uses the media-aware `Optimize-Volume` default on healthy fixed NTFS/ReFS volumes. Requires `-AcknowledgeStorageIo`; consent is per volume. |
| `network.normalize-tcp-autotuning` | `-NormalizeTcpAutoTuning` | Restores only local InternetCustom/DatacenterCustom templates to Normal. Group Policy is never overridden. |
| `network.enable-rss-wired` | `-EnableReceiveSideScaling` | Enables RSS only on supported physical wired adapters. Wireless and unsafe/ambiguous adapters are excluded. |
| `power.best-performance-ac` | `-SetBestPerformancePowerMode` | Windows 11 uses the documented current-user AC mode vote. Windows 10 activates an already-existing High performance plan only. |
| `ux.disable-client-area-animations` | `-DisableClientAnimations` | Changes the current user’s documented client-area animation Boolean through SystemParametersInfo. |
| `startup.review-apps` | `-ReviewStartupApps` | Opens Startup Apps Settings; no entry is changed automatically. |
| `storage.review-storage-sense` | `-ReviewStorageSense` | Opens Storage Sense Settings; Downloads/cloud policies are not changed automatically. |
| `service.<name>` | `-ServiceName <exact-name>` | Verifies a current Microsoft OS binary/ServiceDll, built-in account SID, service type, dependencies, and live state before offering the change. |

## Optional service catalog

No service is Recommended. A Manual-and-Stopped service has no active CPU cost and remains unchanged unless `-DisableDemandStartServices` is supplied. Every service identity is re-read after consent; unknown, repurposed, custom-account, unsigned, non-OS-binary, or changed variants are blocked.

| Exact name | Risk | Bulk eligible | Feature lost while disabled |
|---|---:|---:|---|
| `RetailDemo` | Low | Yes | Retail demonstration mode |
| `wisvc` | Low | Yes | Windows Insider enrollment/preview builds |
| `MapsBroker` | Low | Yes | Downloaded/offline maps |
| `WMPNetworkSvc` | Low | Yes | Media-library sharing to network players |
| `XblAuthManager` | Low | Yes | Xbox Live sign-in and dependent apps |
| `XblGameSave` | Low | Yes | Xbox cloud saves |
| `XboxNetApiSvc` | Low | Yes | Xbox Live networking |
| `Fax` | Medium | No | Fax sending/receiving |
| `icssvc` | Medium | No | Mobile hotspot/connection sharing |
| `SEMgrSvc` | Medium | No | NFC payments/secure element |
| `WalletService` | Medium | No | Windows wallet integrations |
| `XboxGipSvc` | Medium | No | Xbox/adaptive/accessibility controllers |
| `VacSvc` | Medium | No | Mixed Reality spatial audio |
| `spectrum` | Medium | No | Mixed Reality perception/holographic rendering |
| `perceptionsimulation` | Medium | No | Mixed Reality perception simulation |

The signing/path heuristic prevents common OEM or third-party service-name reuse, but it cannot prove semantically that every Microsoft-signed component belongs to a given service on every Windows build. Validate each service on every edition/build in your deployment. `-DisableOptionalServices` selects only the low-risk bulk-eligible subset, then Ask still prompts each service.

## Command-line reference

Use the built-in detailed help for the authoritative reference and examples:

```powershell
Get-Help .\Invoke-WindowsOptimization.ps1 -Detailed
Get-Help .\Invoke-WindowsOptimization.ps1 -Examples
```

Selection:

- `-Category Cleanup,Storage,Network,Power,Services,UserExperience,Startup`
- `-IncludeOptimization <exact IDs>` and `-ExcludeOptimization <exact IDs>`
- `-ServiceName <exact allowlisted names>`
- `-AdapterInterfaceGuid <GUIDs>` and `-VolumeDriveLetter C,D`
- Individual switches from the operations table, `-AllRecommended`, or `-DisableOptionalServices`

Execution and safety:

- `-Mode Audit|Apply|Restore` (default: Audit)
- `-ConsentPolicy Ask|Recommended|YesToAll|NoToAll`
- `-MinimumAgeDays 0..3650` (default: 7); zero requires `-AcknowledgeDeleteAllTempAges`
- `-BackupPath`, `-LogDirectory`, `-ReportPath` only accept protected, local, non-reparse destinations; unsafe ADS/device/trailing-dot aliases are rejected
- `-WhatIf`, `-Confirm`, `-NonInteractive`, `-StopOnError`, `-RequireReliableLogging`, `-PassThru`, `-NoColor`
- `-SkipRestorePoint`, `-AllowManagedDevice`, `-AllowComputerRename`
- `-AllowNetworkChangeInRemoteSession`, `-AcknowledgeNetworkInterruption`
- `-AcknowledgeIrreversibleActions`, `-AcknowledgeStorageIo`, `-AcknowledgeBatteryPowerPlan`
- `-ForceRestoreDivergedState` and `-AcknowledgeServicedServiceIdentityDrift` are separate restore controls; neither bypasses an untrusted or remapped service
- `-IncludeSensitiveAuditData` and `-IncludeStartupCommandLines` opt into otherwise-redacted audit fields

## Rollback

Apply write-ahead journals each reversible operation before mutation and verifies the observed post-state. A failure triggers an immediate operation-level rollback. Restore validates HMAC, schema, exact script version, stable device identity, computer/user scope, record uniqueness, operation allowlists, and current-state divergence before replaying records in reverse order.

```powershell
powershell.exe -NoLogo -NoProfile -File .\Invoke-WindowsOptimization.ps1 `
  -Mode Restore `
  -BackupPath 'C:\ProgramData\WinOptimize\Backups\WinOptimize-backup-YYYYMMDD-HHMMSS-fff.json'
```

Deleted temp/cache data, component-store cleanup, and volume optimization are not reversible. A restore point is best effort, limited by Windows, and is not a personal-file backup.

## Release validation

Run from a clean elevated 64-bit Windows PowerShell 5.1 process on representative Windows 10, Windows 11, and any LTSC images you actually support:

```powershell
Invoke-Pester -Path .\Tests\WinOptimize.Tests.ps1 -Output Detailed
```

Before production approval, also exercise Audit, Apply `-WhatIf`, exact-operation Apply/Restore, forced process termination at each journal boundary, a pending-reboot machine, a managed test endpoint, a remote session, laptop AC/DC transitions, and each allowlisted service present on your images. Include an Automatic (Delayed Start) service round trip to verify the SCM behavior on each supported build. Confirm that `Get-AuthenticodeSignature` reports `Valid` and `IsOSBinary=True` for every eligible service component. Sign the frozen artifact only after these gates pass.

This build received deep first-party research and independent static safety/code reviews, but the supplied Windows/Pester integration gate could not be executed in the non-Windows build environment. It must pass before production deployment.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success or no requested change |
| 1 | Operation/restore failure or divergent state |
| 2 | Fatal preflight/infrastructure failure |
| 3 | Completed with unavailable, blocked, partial, or incomplete-audit results |

## Deliberate exclusions

The script never disables Defender, Firewall, Windows Update, BITS, Event Log, SysMain, page files, memory compression, or core identity/network/servicing services. It never deletes WinSxS manually, uses `/ResetBase`, clears SoftwareDistribution/Installer/Prefetch/browser profiles/event logs/Downloads/OneDrive, disables IPv6, applies legacy TCP registry tweaks, resets Winsock, forces a reboot, or manufactures hidden power plans.

See `report-source.md` for the complete evidence ledger. Key primary sources include Microsoft’s [Windows performance guidance](https://support.microsoft.com/en-us/windows/experience/performance-optimization/tips-to-improve-pc-performance-in-windows), [WinSxS cleanup guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder?view=windows-11), [Optimize-Volume reference](https://learn.microsoft.com/en-us/powershell/module/storage/optimize-volume), [TCP/IP performance guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/tcpip-performance-known-issues), [Win32_Service reference](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service), and [Windows 10 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro).
