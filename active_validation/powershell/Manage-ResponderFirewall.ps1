[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Add", "Remove", "Exists")]
    [string]$Action,

    [Parameter(Mandatory)]
    [ValidatePattern("^CSA-VALIDATION-[A-Fa-f0-9-]+-(LLMNR|NBTNS|HTTP)$")]
    [string]$RuleName,

    [ValidateSet("TCP", "UDP")]
    [string]$Protocol = "TCP",

    [ValidateRange(1, 65535)]
    [int]$LocalPort = 8080,

    [string]$LocalAddress,

    [string]$RemoteAddress,

    [string]$NetworkInterface,

    [ValidateSet("Domain", "Private", "Public")]
    [string]$Profile = "Private",

    [string]$Program
)

$ErrorActionPreference = "Stop"

if ($Action -eq "Remove") {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    exit 0
}

if ($Action -eq "Exists") {
    $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($null -ne $rule) {
        exit 3
    }
    exit 0
}

if (
    -not $LocalAddress -or
    -not $RemoteAddress -or
    -not $NetworkInterface -or
    -not $Program
) {
    throw (
        "Scoped firewall creation requires interface, local, remote, " +
        "and program values."
    )
}

$interfaceAddress = Get-NetIPAddress `
    -InterfaceAlias $NetworkInterface `
    -AddressFamily IPv4 `
    -IPAddress $LocalAddress `
    -ErrorAction SilentlyContinue
if ($null -eq $interfaceAddress) {
    throw "Listener address does not belong to the scoped interface."
}

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol $Protocol `
    -LocalPort $LocalPort `
    -LocalAddress $LocalAddress `
    -RemoteAddress $RemoteAddress `
    -Profile $Profile `
    -Program $Program `
    -PolicyStore ActiveStore | Out-Null
