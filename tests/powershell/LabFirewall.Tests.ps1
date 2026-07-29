BeforeAll {
    $module = Join-Path $PSScriptRoot (
        "..\..\csa_lab\powershell\FirewallArguments.psm1"
    )
    Import-Module $module -Force
}

Describe "CSA Lab firewall process arguments" {
    It "preserves spaced rule names and installed program paths" {
        $values = @(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=CSA Lab Temporary CSA-2026-TEST ABC12345",
            "dir=in",
            "action=allow",
            "program=C:\Users\Example User\AppData\Local\Programs\CSA Lab\CSA-Lab.exe",
            "protocol=TCP",
            "localip=192.168.12.152",
            "localport=8443",
            "remoteip=192.168.12.0/24",
            "profile=Private",
            "enable=yes"
        )

        $actual = Join-CSAProcessArguments -Values $values

        $actual | Should -Be (
            'advfirewall firewall add rule ' +
            '"name=CSA Lab Temporary CSA-2026-TEST ABC12345" ' +
            'dir=in action=allow ' +
            '"program=C:\Users\Example User\AppData\Local\Programs\CSA Lab\CSA-Lab.exe" ' +
            'protocol=TCP localip=192.168.12.152 localport=8443 ' +
            'remoteip=192.168.12.0/24 profile=Private enable=yes'
        )
    }

    It "rejects command-line control characters and quotes" {
        {
            ConvertTo-CSAProcessArgument -Value "name=unsafe`nrule"
        } | Should -Throw
        {
            ConvertTo-CSAProcessArgument -Value 'name=unsafe"rule'
        } | Should -Throw
    }

    It "passes one encoded argument line to elevated netsh" {
        $helper = Get-Content -Raw -LiteralPath (
            Join-Path $PSScriptRoot (
                "..\..\csa_lab\powershell\Invoke-CSAFirewallAction.ps1"
            )
        )

        $helper | Should -Match (
            '\$argumentLine\s*=\s*Join-CSAProcessArguments'
        )
        $helper | Should -Match '-ArgumentList\s+\$argumentLine'
        $helper | Should -Not -Match '-ArgumentList\s+\$arguments'
    }
}
