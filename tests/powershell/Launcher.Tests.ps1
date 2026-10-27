BeforeAll {
    $template = Join-Path $PSScriptRoot '../../csa_lab/powershell/Start-CSACollector.ps1.in'
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($template, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Launcher template syntax failed.' }
    foreach ($node in $ast.EndBlock.Statements) {
        if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
    }
    Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1')
    function New-SyntheticLauncherBinding {
        [pscustomobject]@{ schemaVersion='1.0'; assessmentId='CSA-DEMO'; sessionId='SES-DEMO'
            collectionProfile='windows-standard-v1'; collectionProfileDigest=('sha256:' + ('a'*64))
            serverCertificateFingerprint=('sha256:' + ('b'*64)); packageDigest=('sha256:' + ('c'*64))
            manifestDigest=('sha256:' + ('d'*64)); expiration=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o')
            downloadCredential=('e'*43); serverUrl='https://127.0.0.1:8443'; packageSize=1024; scriptSignerThumbprint='' }
    }
}

Describe 'One-file launcher trust and execution boundaries' {
    It 'accepts a complete future session binding and rejects expired or malformed bindings' {
        $binding = New-SyntheticLauncherBinding
        { Test-CSABootstrapBinding $binding } | Should -Not -Throw
        $binding.expiration = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
        { Test-CSABootstrapBinding $binding } | Should -Throw '*CSA-BOOT-EXPIRED*'
        $binding = New-SyntheticLauncherBinding
        $binding.serverUrl='http://127.0.0.1:8443'
        { Test-CSABootstrapBinding $binding } | Should -Throw '*CSA-BOOT-TLS*'
        $binding = New-SyntheticLauncherBinding
        $binding.serverUrl='https://user:secret@127.0.0.1:8443/?token=secret'
        { Test-CSABootstrapBinding $binding } | Should -Throw '*CSA-BOOT-TLS*'
    }
    It 'rejects unsafe Windows paths rather than normalizing them into trusted names' {
        foreach ($path in @('../x','/x','C:/x','a/../x','a\\x','a/CON.ps1','a/x:ads','a/x.','a//x')) {
            { Resolve-CSABootstrapPath 'C:\Synthetic' $path } | Should -Throw '*CSA-BOOT-PATH*'
        }
    }
    It 'refuses elevated execution without requesting elevation' {
        Mock New-Object {
            $principal=[pscustomobject]@{}
            $principal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value { return $true }
            return $principal
        } -ParameterFilter { $TypeName -eq 'Security.Principal.WindowsPrincipal' }
        { Test-CSABootstrapPrivilege } | Should -Throw '*CSA-BOOT-ELEVATED*'
    }
    It 'rejects invalid signatures and enforces a required publisher' {
        $file = Join-Path $TestDrive 'module.psm1'
        Set-Content -LiteralPath $file -Value '# synthetic module'
        foreach ($status in @('HashMismatch','NotTrusted','UnknownError','NotSupported')) {
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status=$status; SignerCertificate=$null } }
            { Test-CSABootstrapSignature $file } | Should -Throw '*CSA-BOOT-SIGNATURE*'
        }
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status='NotSigned'; SignerCertificate=$null } }
        { Test-CSABootstrapSignature $file ('a'*40) } | Should -Throw '*CSA-BOOT-SIGNATURE*'
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status='Valid'; SignerCertificate=[pscustomobject]@{Thumbprint=('a'*40)} } }
        { Test-CSABootstrapSignature $file ('b'*40) } | Should -Throw '*CSA-BOOT-SIGNATURE*'
        { Test-CSABootstrapSignature $file ('a'*40) } | Should -Not -Throw
    }
    It 'stops an expired session before download or temporary material is created' {
        Mock Test-CSABootstrapSignature { }
        Mock Receive-CSABootstrapPackage { throw 'Download should not be called.' }
        Mock New-CSABootstrapDirectory { throw 'Temporary directory should not be created.' }
        $binding = New-SyntheticLauncherBinding
        $binding.expiration=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
        $code=Invoke-CSABootstrap -Binding $binding -LauncherPath 'Synthetic.ps1' 2>$null
        $code | Should -Be 1
        Should -Invoke Receive-CSABootstrapPackage -Times 0 -Exactly
        Should -Invoke New-CSABootstrapDirectory -Times 0 -Exactly
        $null -eq $binding.downloadCredential | Should -BeTrue
    }
    It 'does not alter policy, remove Mark of the Web, or add an execution-policy override to the child' {
        $source=Get-Content -LiteralPath $template -Raw
        $source | Should -Not -Match '(?i)\b(Set-ExecutionPolicy|Unblock-File|Invoke-Expression)\b|DownloadString|ExecutionPolicy|\-Verb\s+RunAs'
    }
}

Describe 'One-file launcher file locks and cleanup' {
    It 'recovers only from transient Windows sharing locks with bounded waits' {
        Mock Start-Sleep { }
        $script:attempts=0
        $result=Invoke-CSABootstrapFileRetry {
            $script:attempts++
            if($script:attempts -le 3) { throw [IO.IOException]::new('Synthetic sharing lock', -2147024864) }
            return 'verified operation'
        }
        $result | Should -Be 'verified operation'
        Should -Invoke Start-Sleep -Times 3 -Exactly
    }
    It 'fails on a persistent lock and never treats a lock as success' {
        Mock Start-Sleep { }
        { Invoke-CSABootstrapFileRetry { throw [IO.IOException]::new('Synthetic sharing lock', -2147024864) } } | Should -Throw '*CSA-BOOT-FILELOCK*'
        Should -Invoke Start-Sleep -Times 8 -Exactly
    }
    It 'does not retry access denied or trust failures' {
        Mock Start-Sleep { }
        { Invoke-CSABootstrapFileRetry { throw [UnauthorizedAccessException]::new('Synthetic access denial') } } | Should -Throw
        { Invoke-CSABootstrapFileRetry { throw 'CSA-BOOT-DIGEST' } } | Should -Throw '*CSA-BOOT-DIGEST*'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
    It 'creates an inheritance-protected temporary directory for only the current SID and SYSTEM' {
        $path=New-CSABootstrapDirectory
        try {
            $acl=Get-Acl -LiteralPath $path
            $acl.AreAccessRulesProtected | Should -BeTrue
            $expected=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')
            foreach($rule in $acl.Access) {
                $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                $expected -contains $sid | Should -BeTrue
            }
        } finally { Remove-CSABootstrapDirectory $path }
        Test-Path -LiteralPath $path | Should -BeFalse
    }
    It 'refuses cleanup paths outside the unique launcher temporary directory' {
        { Remove-CSABootstrapDirectory $env:TEMP } | Should -Throw '*CSA-BOOT-CLEANUP*'
        { Remove-CSABootstrapDirectory 'C:\Synthetic\CSA-Launcher-00000000000000000000000000000000' } | Should -Throw '*CSA-BOOT-CLEANUP*'
    }
}
