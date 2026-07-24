Set-StrictMode -Version 2.0

function Get-CSABrowserVersion {
    param([Parameter(Mandatory = $true)][string[]]$CandidatePaths)

    foreach ($candidate in $CandidatePaths) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            try {
                return [System.Diagnostics.FileVersionInfo]::GetVersionInfo(
                    $candidate
                ).ProductVersion
            } catch {
                return $null
            }
        }
    }
    return $null
}

function Get-CSABrowserEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $errors = @()
    $definitions = @(
        @{
            Name = "EDGE"
            InstalledId = "BROWSER_EDGE_INSTALLED"
            VersionId = "BROWSER_EDGE_VERSION"
            PolicyId = "BROWSER_EDGE_POLICY_PRESENT"
            Paths = @(
                (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"),
                (Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe")
            )
            PolicyPaths = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
            )
        },
        @{
            Name = "CHROME"
            InstalledId = "BROWSER_CHROME_INSTALLED"
            VersionId = "BROWSER_CHROME_VERSION"
            PolicyId = "BROWSER_CHROME_POLICY_PRESENT"
            Paths = @(
                (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
                (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"),
                (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe")
            )
            PolicyPaths = @(
                "HKLM:\SOFTWARE\Policies\Google\Chrome",
                "HKCU:\SOFTWARE\Policies\Google\Chrome"
            )
        },
        @{
            Name = "FIREFOX"
            InstalledId = "BROWSER_FIREFOX_INSTALLED"
            VersionId = "BROWSER_FIREFOX_VERSION"
            PolicyId = "BROWSER_FIREFOX_POLICY_PRESENT"
            Paths = @(
                (Join-Path $env:ProgramFiles "Mozilla Firefox\firefox.exe"),
                (Join-Path ${env:ProgramFiles(x86)} "Mozilla Firefox\firefox.exe")
            )
            PolicyPaths = @(
                "HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
                "HKCU:\SOFTWARE\Policies\Mozilla\Firefox"
            )
        }
    )

    try {
        foreach ($definition in $definitions) {
            $version = Get-CSABrowserVersion @($definition.Paths)
            $installed = -not [string]::IsNullOrWhiteSpace([string]$version)
            $policyPresent = @(
                $definition.PolicyPaths |
                    Where-Object { Test-Path -LiteralPath $_ }
            ).Count -gt 0
            $settings += New-CSASetting `
                ([string]$definition.InstalledId) `
                "Browser" `
                ([bool]$installed) `
                "RUNTIME_STATE" `
                "SUCCESS" `
                90 `
                "FileVersionInfo" `
                "$($definition.Name).Installed"
            $settings += New-CSASetting `
                ([string]$definition.VersionId) `
                "Browser" `
                $(if ($installed) { [string]$version } else { $null }) `
                "RUNTIME_STATE" `
                "SUCCESS" `
                90 `
                "FileVersionInfo" `
                "$($definition.Name).Version"
            $settings += New-CSASetting `
                ([string]$definition.PolicyId) `
                "Browser" `
                ([bool]$policyPresent) `
                "REGISTRY" `
                "SUCCESS" `
                85 `
                "Registry" `
                "$($definition.Name).Policy"
        }
        $settings += New-CSASetting `
            "BROWSER_EXTENSION_INVENTORY_COLLECTED" `
            "Browser" `
            $false `
            "DEFAULT" `
            "SUCCESS" `
            100 `
            "PrivacyPolicy" `
            "includeBrowserExtensions=false"
    } catch {
        $errors += New-CSACollectionError `
            "Browser" `
            (Resolve-CSAExceptionStatus $_) `
            "CSA-BROWSER-COLLECTION-FAILED" `
            $_.Exception.Message
    }

    New-CSAModuleResult `
        -Module "Browser" `
        -Settings $settings `
        -Errors $errors `
        -StartedAt $startedAt
}

Export-ModuleMember -Function Get-CSABrowserEvidence
