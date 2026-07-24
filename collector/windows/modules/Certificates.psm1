Set-StrictMode -Version 2.0

function Get-CSACertificatesEvidence {
    param([string]$PrivacyMode = "Standard")

    $startedAt = (Get-Date).ToUniversalTime()
    $settings = @()
    $certificates = @()
    $errors = @()
    $stores = @(
        @{
            Name = "CURRENT_USER_MY"
            CountId = "CERTIFICATE_CURRENT_USER_MY_COUNT"
            Path = "Cert:\CurrentUser\My"
        },
        @{
            Name = "LOCAL_MACHINE_ROOT"
            CountId = "CERTIFICATE_LOCAL_MACHINE_ROOT_COUNT"
            Path = "Cert:\LocalMachine\Root"
        }
    )

    foreach ($store in $stores) {
        try {
            $items = @(Get-ChildItem -LiteralPath $store.Path -ErrorAction Stop)
            foreach ($certificate in $items) {
                $keySize = $null
                try { $keySize = [int]$certificate.PublicKey.Key.KeySize } catch {}
                $certificates += [ordered]@{
                    Store = [string]$store.Name
                    SubjectIdentifier = Protect-CSAIdentifier `
                        ([string]$certificate.Subject) "Strict"
                    IssuerIdentifier = Protect-CSAIdentifier `
                        ([string]$certificate.Issuer) "Strict"
                    ValidFrom = $certificate.NotBefore.ToUniversalTime().ToString("o")
                    ValidTo = $certificate.NotAfter.ToUniversalTime().ToString("o")
                    SignatureAlgorithm = [string]$certificate.SignatureAlgorithm.FriendlyName
                    PublicKeySize = $keySize
                    HasPrivateKey = [bool]$certificate.HasPrivateKey
                }
            }
            $settings += New-CSASetting `
                ([string]$store.CountId) `
                "Certificates" `
                ([int]$items.Count) `
                "RUNTIME_STATE" `
                "SUCCESS" `
                90 `
                "CertificateProvider" `
                $store.Path
        } catch {
            $errors += New-CSACollectionError `
                "Certificates" `
                (Resolve-CSAExceptionStatus $_) `
                "CSA-CERTIFICATE-STORE-UNAVAILABLE" `
                $_.Exception.Message
        }
    }

    $now = Get-Date
    $settings += New-CSASetting `
        "CERTIFICATE_EXPIRED_COUNT" `
        "Certificates" `
        (@($certificates | Where-Object { [datetime]$_.ValidTo -lt $now }).Count) `
        "RUNTIME_STATE" `
        "SUCCESS" `
        90 `
        "CertificateProvider" `
        "VisibleStores"
    $settings += New-CSASetting `
        "CERTIFICATE_PRIVATE_KEY_PRESENT_COUNT" `
        "Certificates" `
        (@($certificates | Where-Object { [bool]$_.HasPrivateKey }).Count) `
        "RUNTIME_STATE" `
        "SUCCESS" `
        90 `
        "CertificateProvider" `
        "BooleanOnly"

    New-CSAModuleResult `
        -Module "Certificates" `
        -Settings $settings `
        -Errors $errors `
        -StartedAt $startedAt `
        -Certificates $certificates
}

Export-ModuleMember -Function Get-CSACertificatesEvidence
