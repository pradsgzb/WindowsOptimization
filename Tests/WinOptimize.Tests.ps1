#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
        -not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'Release-gate tests must run in 64-bit Windows PowerShell 5.1 Desktop.'
    }

    $script:SutPath = (Resolve-Path (Join-Path $PSScriptRoot '..\Invoke-WindowsOptimization.ps1')).Path
    $tokens = $null
    $parseErrors = $null
    $script:SutAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:SutPath,
        [ref]$tokens,
        [ref]$parseErrors)
    $script:SutParseErrors = @($parseErrors)
    $script:SutSource = [IO.File]::ReadAllText($script:SutPath)

    $script:SutModule = New-Module -Name WinOptimizeUnderTest -ArgumentList $script:SutPath -ScriptBlock {
        param($Path)
        . $Path
        Export-ModuleMember -Function *
    }
    Import-Module $script:SutModule -Force
}

AfterAll {
    Remove-Module WinOptimizeUnderTest -Force -ErrorAction SilentlyContinue
}

Describe 'PowerShell 5.1 release surface' {
    It 'parses without errors in the target engine' {
        $script:SutParseErrors | Should -HaveCount 0
    }

    It 'has one definition for every private function' {
        $functions = @($script:SutAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true) | ForEach-Object { $_.Name.ToLowerInvariant() })
        @($functions | Group-Object | Where-Object Count -gt 1) | Should -HaveCount 0
    }

    It 'documents every script parameter in comment-based help' {
        $parameterNames = @($script:SutAst.ParamBlock.Parameters | ForEach-Object {
            $_.Name.VariablePath.UserPath.ToLowerInvariant()
        })
        $helpNames = @([regex]::Matches(
            $script:SutSource,
            '(?im)^\.PARAMETER\s+(?<Name>[A-Za-z][A-Za-z0-9]*)\s*$') | ForEach-Object {
                $_.Groups['Name'].Value.ToLowerInvariant()
            })
        @($parameterNames | Where-Object { $helpNames -notcontains $_ }) | Should -HaveCount 0
    }

    It 'contains none of the prohibited blanket tuning commands' {
        $script:SutSource | Should -Not -Match '(?i)/ResetBase\b'
        $script:SutSource | Should -Not -Match '(?i)TcpAckFrequency|TCPNoDelay'
        $script:SutSource | Should -Not -Match '(?i)Disable-NetAdapterPowerManagement'
        $script:SutSource | Should -Not -Match '(?i)netsh\s+.*(?:chimney|netdma)'
    }

    It 'keeps the executable entry point and trust bootstrap alias-proof' {
        $script:SutSource | Should -Match '&\s+\$\{function:Invoke-WinOptimizeMain\}'
        $script:SutSource | Should -Match '&\s+\$\{function:Initialize-TrustedCommandEnvironment\}'
        $script:SutSource | Should -Match 'FunctionDefinitionAst'
        $script:SutSource | Should -Match 'Get-Alias\s+-ErrorAction\s+Stop'
    }

    It 'keeps the requested service and folder consent labels with Y N A choices' {
        $script:SutSource | Should -Match 'Disable Service\?'
        $script:SutSource | Should -Match 'Delete eligible contents from temporary folder\?'
        $script:SutSource | Should -Match '\[Y\] Yes\s+\[N\] No\s+\[A\] All remaining'
    }
}

Describe 'Catalog safety invariants' {
    InModuleScope WinOptimizeUnderTest {
        BeforeAll {
            $script:Catalog = @(Get-OptimizationCatalog)
        }

        It 'has unique case-insensitive operation IDs' {
            @($script:Catalog.Id | ForEach-Object { $_.ToLowerInvariant() } |
                Group-Object | Where-Object Count -gt 1) | Should -HaveCount 0
        }

        It 'never marks a service as recommended' {
            @($script:Catalog | Where-Object { $_.Kind -eq 'Service' -and $_.Recommended }) |
                Should -HaveCount 0
        }

        It 'keeps critical and allowlisted service names disjoint' {
            $allowlisted = @($script:Catalog | Where-Object Kind -eq 'Service' |
                ForEach-Object { $_.ServiceName.ToLowerInvariant() })
            @($script:CriticalServiceDenylist | Where-Object {
                $allowlisted -contains $_.ToLowerInvariant()
            }) | Should -HaveCount 0
        }

        It 'requires explicit selection for every medium-risk service' {
            @($script:Catalog | Where-Object {
                $_.Kind -eq 'Service' -and $_.Risk -eq 'Medium' -and $_.BulkEligible
            }) | Should -HaveCount 0
        }

        It 'keeps Xbox adaptive/accessibility input outside bulk approval' {
            $xboxGip = @($script:Catalog | Where-Object ServiceName -eq 'XboxGipSvc')
            $xboxGip | Should -HaveCount 1
            $xboxGip[0].Risk | Should -Be 'Medium'
            $xboxGip[0].BulkEligible | Should -BeFalse
        }
    }
}

Describe 'Consent scoping' {
    InModuleScope WinOptimizeUnderTest {
        BeforeEach {
            $ConsentPolicy = 'Ask'
            $NonInteractive = $false
            $script:IsWhatIf = $false
            $script:ConsentAllByGroup = @{}
            $script:ReadAnswers = @()
            $script:ReadIndex = 0
            Mock Write-Log { }
            Mock Write-Host { }
            Mock Write-UiHost { }
            Mock Read-Host {
                $answer = $script:ReadAnswers[$script:ReadIndex]
                $script:ReadIndex++
                return $answer
            }
        }

        It 'accepts Y and N case-insensitively' {
            $operation = New-Operation -Id 'test.one' -Category 'Cleanup' -DisplayName 'Test' `
                -Description 'Test' -Impact 'Test' -Risk Low -Recommended $false -Reversible $false -Kind 'Test'
            $script:ReadAnswers = @('y', 'n')
            (Request-OperationConsent -Operation $operation) | Should -BeTrue
            (Request-OperationConsent -Operation $operation) | Should -BeFalse
            $script:ReadIndex | Should -Be 2
        }

        It 'scopes A to the same category and risk only' {
            $lowCleanupA = New-Operation -Id 'test.a' -Category 'Cleanup' -DisplayName 'A' -Description 'A' -Impact 'A' -Risk Low -Recommended $false -Reversible $false -Kind 'Test'
            $lowCleanupB = New-Operation -Id 'test.b' -Category 'Cleanup' -DisplayName 'B' -Description 'B' -Impact 'B' -Risk Low -Recommended $false -Reversible $false -Kind 'Test'
            $mediumCleanup = New-Operation -Id 'test.c' -Category 'Cleanup' -DisplayName 'C' -Description 'C' -Impact 'C' -Risk Medium -Recommended $false -Reversible $false -Kind 'Test'
            $lowService = New-Operation -Id 'test.d' -Category 'Services' -DisplayName 'D' -Description 'D' -Impact 'D' -Risk Low -Recommended $false -Reversible $true -Kind 'Test'
            $script:ReadAnswers = @('A', 'N', 'N')

            (Request-OperationConsent -Operation $lowCleanupA) | Should -BeTrue
            (Request-OperationConsent -Operation $lowCleanupB) | Should -BeTrue
            (Request-OperationConsent -Operation $mediumCleanup) | Should -BeFalse
            (Request-OperationConsent -Operation $lowService) | Should -BeFalse
            $script:ReadIndex | Should -Be 3
        }

        It 'does not prompt during WhatIf' {
            $script:IsWhatIf = $true
            $operation = New-Operation -Id 'test.whatif' -Category 'Cleanup' -DisplayName 'Test' `
                -Description 'Test' -Impact 'Test' -Risk Low -Recommended $false -Reversible $false -Kind 'Test'
            (Request-OperationConsent -Operation $operation) | Should -BeTrue
            Assert-MockCalled Read-Host -Times 0 -Exactly
        }
    }
}

Describe 'Operational file path policy' {
    InModuleScope WinOptimizeUnderTest {
        It 'accepts an ordinary canonical drive-letter file path' {
            (Assert-SafeOperationalFilePath -Path 'C:\ProgramData\WinOptimize\Backups\state.json' -Purpose Test) |
                Should -Be 'C:\ProgramData\WinOptimize\Backups\state.json'
        }

        It 'rejects <Case>' -TestCases @(
            @{ Case = 'alternate data stream'; Path = 'C:\ProgramData\WinOptimize\state.json:evil' },
            @{ Case = 'reserved device'; Path = 'C:\ProgramData\WinOptimize\CON.json' },
            @{ Case = 'trailing dot'; Path = 'C:\ProgramData\WinOptimize\state.json.' },
            @{ Case = 'trailing space'; Path = 'C:\ProgramData\WinOptimize\state.json ' },
            @{ Case = 'relative segment'; Path = 'C:\ProgramData\WinOptimize\..\state.json' },
            @{ Case = 'wildcard'; Path = 'C:\ProgramData\WinOptimize\*.json' },
            @{ Case = 'UNC path'; Path = '\\server\share\state.json' }
        ) {
            { Assert-SafeOperationalFilePath -Path $Path -Purpose Test } | Should -Throw
        }
    }
}

Describe 'Service identity and restore semantics' {
    InModuleScope WinOptimizeUnderTest {
        BeforeAll {
            function New-TestServiceState {
                param([string]$Hash, [string]$Thumbprint, [string]$StartMode = 'Manual', [string]$State = 'Stopped')
                return [pscustomobject][ordered]@{
                    Name = 'Fax'
                    BinaryPathName = 'C:\Windows\System32\fxssvc.exe'
                    AccountName = 'NT AUTHORITY\NetworkService'
                    ServiceType = 'Own Process'
                    Identity = [pscustomobject][ordered]@{
                        AccountSid = 'S-1-5-20'
                        RegistryType = [uint32]0x10
                        Image = [pscustomobject][ordered]@{
                            Path = 'C:\Windows\System32\fxssvc.exe'
                            Sha256 = $Hash
                            Length = 12345
                            SignatureStatus = 'Valid'
                            SignatureType = 'Catalog'
                            IsOsBinary = $true
                            SignerThumbprint = $Thumbprint
                            SignerSubject = 'CN=Microsoft Windows, O=Microsoft Corporation, C=US'
                        }
                        ServiceDll = $null
                    }
                    StartMode = $StartMode
                    DelayedAutoStart = $false
                    State = $State
                    Started = ($State -eq 'Running')
                }
            }
        }

        It 'tolerates trusted servicing fingerprints in long-lived target comparison' {
            $old = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $serviced = New-TestServiceState -Hash (('c' * 64) -join '') -Thumbprint (('d' * 40) -join '')
            (Test-RestoreStateEquivalent -Kind Service -Left $old -Right $serviced) | Should -BeTrue
            (Test-ServiceIdentityFingerprintEquivalent -Left $old -Right $serviced) | Should -BeFalse
        }

        It 'includes stable component mapping in target comparison' {
            $left = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $right = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $right.Identity.Image.Path = 'C:\Windows\System32\not-fax.exe'
            (Test-RestoreStateEquivalent -Kind Service -Left $left -Right $right) | Should -BeFalse
        }

        It 'detects raw mapping drift when signed component evidence is unchanged' {
            $baseline = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $changedCommandLine = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $changedCommandLine.BinaryPathName = 'C:\Windows\System32\fxssvc.exe -unexpected'
            $changedAccount = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $changedAccount.AccountName = 'UnexpectedAccount'
            $changedType = New-TestServiceState -Hash (('a' * 64) -join '') -Thumbprint (('b' * 40) -join '')
            $changedType.ServiceType = 'Share Process'

            Test-ServiceStableMappingEquivalent -Left $baseline -Right $baseline | Should -BeTrue
            Test-ServiceStableMappingEquivalent -Left $baseline -Right $changedCommandLine | Should -BeFalse
            Test-ServiceStableMappingEquivalent -Left $baseline -Right $changedAccount | Should -BeFalse
            Test-ServiceStableMappingEquivalent -Left $baseline -Right $changedType | Should -BeFalse
        }

        It 'rejects every critical service before parsing identity evidence' {
            $operation = [pscustomobject]@{ Id = 'service.windefend'; ServiceName = 'WinDefend' }
            $state = [pscustomobject]@{ Name = 'WinDefend' }
            { Assert-RestoreStateSafe -Kind Service -State $state -Operation $operation -Label BeforeState } |
                Should -Throw
        }

        It 'maps built-in service accounts to fixed SIDs' {
            (Resolve-ServiceAccountSid -AccountName LocalSystem -ServiceName Fax) | Should -Be 'S-1-5-18'
            (Resolve-ServiceAccountSid -AccountName 'NT AUTHORITY\LocalService' -ServiceName Fax) | Should -Be 'S-1-5-19'
            (Resolve-ServiceAccountSid -AccountName 'NT AUTHORITY\NetworkService' -ServiceName Fax) | Should -Be 'S-1-5-20'
        }
    }
}

Describe 'Authenticated manifest semantic validation' {
    InModuleScope WinOptimizeUnderTest {
        BeforeEach {
            $AllowComputerRename = $false
            Mock Assert-RestoreRecordSafe { }
        }

        It 'rejects duplicate operation IDs case-insensitively' {
            $manifest = [pscustomobject]@{
                SchemaVersion = $script:SchemaVersion
                ScriptName = $script:ScriptName
                ScriptVersion = $script:ScriptVersion
                Machine = [pscustomobject]@{ DeviceIdentityHash = 'device'; ComputerName = 'PC1' }
                Records = @(
                    [pscustomobject]@{ Id = 'service.fax' },
                    [pscustomobject]@{ Id = 'SERVICE.FAX' }
                )
            }
            $osInfo = [pscustomobject]@{ DeviceIdentityHash = 'device'; ComputerName = 'PC1' }
            { Assert-RestoreManifestSafe -Manifest $manifest -OsInfo $osInfo -Catalog @() } | Should -Throw
        }
    }
}

Describe 'Component-store sequencing' {
    InModuleScope WinOptimizeUnderTest {
        BeforeEach {
            $script:Results = New-Object System.Collections.ArrayList
            Mock Request-OperationConsent { $true }
            Mock Test-ShouldProcessOperation { $true }
            Mock Get-MaintenanceBlockMessage { $null }
            Mock Get-LongMaintenancePowerBlockMessage { $null }
            Mock New-ChangeRecord {
                [pscustomobject]@{ Status = 'Prepared'; AfterState = $null; Message = $null }
            }
            Mock Complete-ChangeRecord { }
            Mock Write-Log { }
            Mock Invoke-Dism {
                [pscustomobject]@{ ExitCode = 3010; RestartRequired = $true; Output = @() }
            }
        }

        It 'does not start cleanup when analysis reports restart required' {
            $operation = [pscustomobject]@{
                Id = 'storage.component-store-cleanup'
                Category = 'Storage'
                Kind = 'ComponentStore'
                DisplayName = 'Component cleanup'
                Reversible = $false
            }

            $result = Invoke-ComponentStoreOperation -Operation $operation

            $result.Status | Should -Be 'Blocked'
            $result.RestartRequired | Should -BeTrue
            Should -Invoke Invoke-Dism -Times 1 -Exactly -ParameterFilter {
                $Arguments -contains '/AnalyzeComponentStore'
            }
            Should -Invoke Invoke-Dism -Times 0 -Exactly -ParameterFilter {
                $Arguments -contains '/StartComponentCleanup'
            }
        }
    }
}

Describe 'Native temporary-file deletion' -Tag 'WindowsIntegration' {
    InModuleScope WinOptimizeUnderTest {
        BeforeAll {
            Initialize-NativeMethods
        }

        It 'walks ordinary file and directory parents without a StrictMode property error' {
            $root = Join-Path $TestDrive 'ordinary-path-root'
            $null = New-Item -ItemType Directory -Path $root
            $file = Join-Path $root 'ordinary.tmp'
            Set-Content -LiteralPath $file -Value 'fixture'

            Test-PathContainsReparsePoint -Path $file | Should -BeFalse
            Test-PathContainsReparsePoint -Path $root | Should -BeFalse
        }

        It 'deletes an old regular fixture by handle while preserving its folder' {
            $root = Join-Path $TestDrive 'approved-root'
            $null = New-Item -ItemType Directory -Path $root
            $file = Join-Path $root 'old.tmp'
            Set-Content -LiteralPath $file -Value 'fixture'
            (Get-Item -LiteralPath $file).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-10)

            $result = Remove-OldRegularTempFile -Path $file -Root $root -CutoffUtc ([DateTime]::UtcNow.AddDays(-7))

            $result.Status | Should -Be 'Deleted'
            Test-Path -LiteralPath $file | Should -BeFalse
            Test-Path -LiteralPath $root -PathType Container | Should -BeTrue
        }

        It 'preserves a recent regular fixture' {
            $root = Join-Path $TestDrive 'recent-root'
            $null = New-Item -ItemType Directory -Path $root
            $file = Join-Path $root 'recent.tmp'
            Set-Content -LiteralPath $file -Value 'fixture'

            $result = Remove-OldRegularTempFile -Path $file -Root $root -CutoffUtc ([DateTime]::UtcNow.AddDays(-7))

            $result.Status | Should -Be 'Recent'
            Test-Path -LiteralPath $file -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $root -PathType Container | Should -BeTrue
        }
    }
}

Describe 'Interactive user identity binding' -Tag 'WindowsIntegration' {
    InModuleScope WinOptimizeUnderTest {
        BeforeAll {
            Initialize-NativeMethods
        }

        It 'binds the elevated token to the owner of the current interactive session' {
            $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Test-IsInteractiveUserContext -UserSid $currentSid | Should -BeTrue
        }

        It 'refuses a different token SID in the same session' {
            Test-IsInteractiveUserContext -UserSid 'S-1-5-32-544' | Should -BeFalse
        }
    }
}
