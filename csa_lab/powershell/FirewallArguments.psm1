Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function ConvertTo-CSAProcessArgument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if (
        $Value.IndexOf([char]0) -ge 0 -or
        $Value.Contains("`r") -or
        $Value.Contains("`n") -or
        $Value.Contains('"')
    ) {
        throw "CSA firewall argument contains unsupported characters."
    }
    if ($Value -match "\s") {
        return '"' + $Value + '"'
    }
    return $Value
}

function Join-CSAProcessArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Values
    )

    if ($Values.Count -eq 0) {
        throw "CSA firewall argument list cannot be empty."
    }
    return (
        $Values |
        ForEach-Object { ConvertTo-CSAProcessArgument -Value $_ }
    ) -join " "
}

Export-ModuleMember -Function @(
    "ConvertTo-CSAProcessArgument",
    "Join-CSAProcessArguments"
)
