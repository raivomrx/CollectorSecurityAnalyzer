BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../collector/windows/modules/Privacy.psm1') -Force
    $policyPath=Join-Path $PSScriptRoot '../../collector/windows/profiles/privacy-default.json'
    $policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    $context=@{assessmentId='CSA-SYNTHETIC-A'; key=[Convert]::ToBase64String([byte[]](1..32))}
}

Describe 'Profile privacy fail-closed boundaries' {
    It 'rejects a malformed policy or context before returning evidence' {
        $bad=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
        $bad.includeHostname='false'
        { Invoke-CSACollectionPrivacy @{device=@{hostname='SYNTHETIC'}} $bad $context } | Should -Throw '*CSA-PRIVACY-POLICY*'
        { Invoke-CSACollectionPrivacy @{device=@{hostname='SYNTHETIC'}} $policy @{key='invalid';assessmentId='synthetic'} } | Should -Throw '*CSA-PRIVACY-CONTEXT*'
    }
    It 'keeps device pseudonyms stable across sessions within an assessment' {
        $first=Get-CSAPrivacyDeviceId 'SYNTHETIC-HOST' $context
        $first | Should -Match '^sha256:[a-f0-9]{64}$'
        Get-CSAPrivacyDeviceId 'synthetic-host' $context | Should -Be $first
        $other=@{assessmentId='CSA-SYNTHETIC-B';key=$context.key}
        Get-CSAPrivacyDeviceId 'SYNTHETIC-HOST' $other | Should -Not -Be $first
        Get-CSAPrivacyDeviceId 'SYNTHETIC-OTHER' $context | Should -Not -Be $first
    }
    It 'does not mutate the input document or export its context key' {
        $source=@{device=@{hostname='SYNTHETIC-HOST'};metadata=@{}}
        $result=Invoke-CSACollectionPrivacy $source $policy $context
        $source.device.hostname | Should -Be 'SYNTHETIC-HOST'
        $result.device.hostname | Should -Match '^id-[a-f0-9]{24}$'
        $json=$result | ConvertTo-Json -Depth 24
        $json | Should -Not -Match ([regex]::Escape($context.key))
        $result.metadata.privacyMode | Should -Be 'PROFILE_ENFORCED'
    }
}
