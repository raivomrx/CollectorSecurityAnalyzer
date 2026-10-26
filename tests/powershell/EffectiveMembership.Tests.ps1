BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../collector/windows/modules/General.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../collector/windows/modules/Accounts.psm1') -Force
}

Describe 'ACC-011 native execution-token evidence' {
    BeforeEach {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General {
            [pscustomobject]@{
                SubjectSid = 'S-1-5-21-100-200-300-1001'; IsElevated = $false
                IntegrityLevel = 'MEDIUM'; ElevationType = 'LIMITED'; GroupsStatus = 'SUCCESS'
                AdministratorSidPresent = $true; AdministratorAttributes = 16
                MatchedGroups = @([pscustomobject]@{ Sid = 'S-1-5-21-100-200-300-512'; Attributes = 16 })
            }
        }
    }
    It 'preserves deny-only membership without claiming an elevated process' {
        $value = Get-CSAExecutionTokenContext -PrivacyMode Standard
        $value.isElevated | Should -BeFalse
        $value.isLocalAdministratorMember | Should -BeTrue
        $value.executionMode | Should -Be ADMIN_MEMBER_NOT_ELEVATED
        $value.administratorMembership.administratorGroupDenyOnly | Should -BeTrue
        $value.administratorMembership.administratorGroupEnabled | Should -BeFalse
        $value.administratorMembership.elevationType | Should -Be LIMITED
        $value.administratorMembership.provider | Should -Be GetTokenInformation
        $value.administratorMembership.groupsComplete | Should -BeTrue
    }
    It 'pseudonymizes subject and matched domain groups under strict privacy' {
        $value = Get-CSAExecutionTokenContext -PrivacyMode Strict
        $value.administratorMembership.subjectSid | Should -Match '^id-[0-9a-f]{12}$'
        $value.administratorMembership.matchedAdministratorGroups[0].sid | Should -Match '^id-[0-9a-f]{12}$'
        $value.administratorMembership.administratorSid | Should -Be S-1-5-32-544
        $json = $value | ConvertTo-Json -Depth 10
        $json | Should -Not -Match 'S-1-5-21-100-200-300'
        $json | Should -Not -Match 'TokenHandle|LinkedToken|AccessToken'
    }
    It 'uses an absent administrator SID only after a complete native query' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General {
            [pscustomobject]@{ SubjectSid = 'S-1-5-21-100-200-300-1001'; IsElevated = $false
                IntegrityLevel = 'MEDIUM'; ElevationType = 'DEFAULT'; GroupsStatus = 'SUCCESS'
                AdministratorSidPresent = $false; AdministratorAttributes = $null; MatchedGroups = @() }
        }
        $value = Get-CSAExecutionTokenContext
        $value.isLocalAdministratorMember | Should -BeFalse
        $value.administratorMembership.groupsComplete | Should -BeTrue
        $value.administratorMembership.administratorSidPresent | Should -BeFalse
        $null -eq $value.administratorMembership.administratorGroupAttributes | Should -BeTrue
    }
    It 'retains unknown membership when native groups fail despite a known medium integrity' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General {
            [pscustomobject]@{ SubjectSid = 'S-1-5-21-100-200-300-1001'; IsElevated = $false
                IntegrityLevel = 'MEDIUM'; ElevationType = 'LIMITED'; GroupsStatus = 'FAILED'
                AdministratorSidPresent = $false; AdministratorAttributes = $null; MatchedGroups = @() }
        }
        $value = Get-CSAExecutionTokenContext
        $null -eq $value.isLocalAdministratorMember | Should -BeTrue
        $null -eq $value.administratorMembership.administratorSidPresent | Should -BeTrue
        $value.administratorMembership.groupsComplete | Should -BeFalse
        $value.administratorMembership.collectionStatus | Should -Be FAILED
        $value.administratorMembership.errorCode | Should -Be TOKEN_GROUPS_QUERY_FAILED
    }
    It 'cannot turn provider or whoami failure into a false administrator boolean' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General { throw 'Synthetic unavailable provider' }
        Mock Invoke-CSAIntegrityGroupQuery -ModuleName General {
            [pscustomobject]@{ ExitCode = 5; Lines = @('"Synthetic","Label","S-1-16-8192",""', '"Synthetic","Group","S-1-5-32-544",""') }
        }
        $value = Get-CSAExecutionTokenContext
        $null -eq $value.isLocalAdministratorMember | Should -BeTrue
        $value.administratorMembership.collectionStatus | Should -Be FAILED
        $value.administratorMembership.groupsComplete | Should -BeFalse
        $value.administratorMembership.errorCode | Should -Be TOKEN_QUERY_UNAVAILABLE
        $value.integrityLevel | Should -Be UNKNOWN
        Should -Invoke Invoke-CSAIntegrityGroupQuery -ModuleName General -Exactly -Times 1
    }
    It 'keeps enabled membership and actual elevation separate' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General {
            [pscustomobject]@{ SubjectSid = 'S-1-5-21-100-200-300-1001'; IsElevated = $true
                IntegrityLevel = 'HIGH'; ElevationType = 'FULL'; GroupsStatus = 'SUCCESS'
                AdministratorSidPresent = $true; AdministratorAttributes = 4; MatchedGroups = @() }
        }
        $value = Get-CSAExecutionTokenContext
        $value.isLocalAdministratorMember | Should -BeTrue
        $value.isElevated | Should -BeTrue
        $value.executionMode | Should -Be ELEVATED_ADMINISTRATOR
        $value.administratorMembership.administratorGroupEnabled | Should -BeTrue
        $value.administratorMembership.administratorGroupDenyOnly | Should -BeFalse
    }
    It 'preserves unknown membership if both native and fallback executables are unavailable' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General { throw 'Synthetic blocked provider' }
        Mock Invoke-CSAIntegrityGroupQuery -ModuleName General { throw 'Synthetic unavailable executable' }
        $value = Get-CSAExecutionTokenContext
        $null -eq $value.isLocalAdministratorMember | Should -BeTrue
        $value.integrityLevel | Should -Be UNKNOWN
        $value.administratorMembership.groupsComplete | Should -BeFalse
    }
    It 'does not mistake a disabled administrator SID for a standard account' {
        Mock Invoke-CSANativeTokenSnapshot -ModuleName General {
            [pscustomobject]@{ SubjectSid = 'S-1-5-21-100-200-300-1001'; IsElevated = $false
                IntegrityLevel = 'MEDIUM'; ElevationType = 'DEFAULT'; GroupsStatus = 'SUCCESS'
                AdministratorSidPresent = $true; AdministratorAttributes = 0; MatchedGroups = @() }
        }
        $value = Get-CSAExecutionTokenContext
        $null -eq $value.isLocalAdministratorMember | Should -BeTrue
        $value.administratorMembership.administratorSidPresent | Should -BeTrue
        $value.administratorMembership.administratorGroupEnabled | Should -BeFalse
        $value.administratorMembership.administratorGroupDenyOnly | Should -BeFalse
    }
}

Describe 'Windows token integration with no elevation or token modification' {
    It 'queries only the current token and returns only explicitly requested group intersections' {
        $native = Invoke-CSANativeTokenSnapshot -AdministratorGroupSids @('S-1-5-32-545')
        $native.GroupsStatus | Should -Be SUCCESS
        @($native.MatchedGroups | Where-Object Sid -ne 'S-1-5-32-545').Count | Should -Be 0
        $native.SubjectSid | Should -Match '^S-1-'
        $private = Get-CSAExecutionTokenContext -PrivacyMode Strict
        $private.administratorMembership.collectionStatus | Should -Be SUCCESS
        $private.administratorMembership.subjectSid | Should -Match '^id-[0-9a-f]{12}$'
        @($private.administratorMembership.matchedAdministratorGroups).Count | Should -Be 0
    }
    It 'keeps collected execution-account and desktop-user scopes separate' {
        Mock Get-LocalUser -ModuleName Accounts {
            [pscustomobject]@{ Name = 'Synthetic'; SID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                PrincipalSource = 'Local'; Enabled = $true; PasswordRequired = $true
                PasswordExpires = $null; PasswordNeverExpires = $false; LastLogon = $null }
        }
        Mock Get-LocalGroupMember -ModuleName Accounts { @() }
        Mock Get-CimInstance -ModuleName Accounts { @() }
        $result = Get-CSAAccountsEvidence -PrivacyMode Strict -PasswordPolicyProvider {
            param($level)
            if ($level -eq 0) { return @{ MinimumLength=15; MaximumAge=0; MinimumAge=0; HistoryLength=24 } }
            return @{ LockoutDuration=900; ObservationWindow=900; LockoutThreshold=10 }
        }
        $current = @($result.Settings | Where-Object settingId -eq CURRENT_EXECUTION_USER)[0]
        $desktop = @($result.Settings | Where-Object settingId -eq LOGGED_ON_USERS)[0]
        $token = @($result.Settings | Where-Object settingId -eq EXECUTION_TOKEN_ADMIN_MEMBERSHIP)[0]
        $current.effectiveValue.ObservationScope | Should -Be COLLECTOR_EXECUTION_ACCOUNT
        $current.effectiveValue.Classification | Should -Be LOCAL
        $current.effectiveValue.Sid | Should -Match '^id-[0-9a-f]{12}$'
        $desktop.collectionStatus | Should -Be NOT_AVAILABLE
        $desktop.errorCode | Should -Be DESKTOP_USERS_NOT_EVALUATED
        @($desktop.effectiveValue).Count | Should -Be 0
        $token.collectionStatus | Should -Be SUCCESS
        $token.effectiveValue.subjectSid | Should -Be $current.effectiveValue.Sid
    }
}
