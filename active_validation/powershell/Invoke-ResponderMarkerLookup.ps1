[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern("^(CSA-RSP-[A-F0-9]{8}-[A-F0-9]{6}|CSAR-[A-F0-9]{10})$")]
    [string]$Marker,

    [Parameter(Mandatory)]
    [ValidateRange(1024, 65535)]
    [int]$ListenerPort,

    [Parameter(Mandatory)]
    [ValidateSet("LLMNR", "NBT_NS")]
    [string]$NameResolutionProtocol,

    [Parameter(Mandatory)]
    [string]$RemoteComputer
)

$ErrorActionPreference = "Stop"
$trigger = {
    param($Name, $Port, $ResolutionProtocol)

    if ($ResolutionProtocol -eq "LLMNR") {
        Resolve-DnsName `
            -Name $Name `
            -LlmnrOnly `
            -NoHostsFile `
            -QuickTimeout `
            -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Resolve-DnsName `
            -Name $Name `
            -LlmnrNetbiosOnly `
            -NoHostsFile `
            -QuickTimeout `
            -ErrorAction SilentlyContinue | Out-Null
    }

    try {
        Invoke-WebRequest `
            -Uri ("http://{0}:{1}/csa-validation" -f $Name, $Port) `
            -UseDefaultCredentials `
            -UseBasicParsing `
            -TimeoutSec 10 | Out-Null
    }
    catch {
        # The one-shot assessment listener may close immediately after Type 3.
    }
}

if (
    $RemoteComputer -eq "." -or
    $RemoteComputer -eq "localhost" -or
    $RemoteComputer -eq $env:COMPUTERNAME
) {
    & $trigger $Marker $ListenerPort $NameResolutionProtocol
}
else {
    Invoke-Command `
        -ComputerName $RemoteComputer `
        -Authentication Negotiate `
        -ScriptBlock $trigger `
        -ArgumentList $Marker, $ListenerPort, $NameResolutionProtocol |
        Out-Null
}
