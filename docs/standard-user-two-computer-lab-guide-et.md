# CSA kahe arvuti standard-user testijuhend

See juhend kirjeldab Sprint 5.0 testimist kahe samas võrgus oleva Windows 11
arvutiga:

```text
Testarvuti, tavakasutaja
    -> HTTPS Collector submission
Laboriarvuti, CSA Console
    -> valideerimine, analüüs ja HTML-raportid
```

Raporteid ei genereerita testarvutis. Testarvuti saadab krüptograafiliselt
seotud evidence-package'i laboriarvuti Console'isse. Endpoint-, fleet-,
executive- ja dashboard-raportid tekivad laboriarvuti `assessments/` kausta.

## 1. Eeldused

Laboriarvutis peab olema:

- CSA repository;
- Python 3.12;
- ligipääs samale kohtvõrgule mis testarvutil;
- assessor-only ligipääs repository ja `assessments/` kaustale;
- vajaduse korral õigus lisada laboriarvutisse ajutine tulemüürireegel.

Testarvutis peab olema:

- Windows 11;
- Windows PowerShell 5.1;
- päris tavakasutaja, kes ei kuulu Local Administrators gruppi;
- tavakasutajana avatud PowerShell, mitte `Run as administrator`.

Testarvutisse ei ole vaja paigaldada Pythonit ega CSA serverit.

Collector ei tohi:

- kuvada UAC dialoogi;
- muuta endpointi registrit või tulemüüri;
- installida teenust, scheduled task'i ega agenti;
- käivitada Active Validationit;
- koguda paroole, browser credentials'eid ega recovery key'sid.

## 2. Leia mõlema arvuti IP-aadressid

Laboriarvutis:

```powershell
Get-NetIPConfiguration |
    Where-Object { $_.IPv4DefaultGateway } |
    Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
```

Testarvutis:

```powershell
Get-NetIPConfiguration |
    Where-Object { $_.IPv4DefaultGateway } |
    Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
```

Märgi üles:

```text
LAB_IP  = laboriarvuti IPv4 aadress, näiteks 192.168.10.20
TEST_IP = testarvuti IPv4 aadress, näiteks 192.168.10.31
PORT    = 8443
```

Ära kasuta Console'i aadressina `0.0.0.0`, `::`, `127.0.0.1` ega Wi-Fi/VPN
adapteri aadressi, mille kaudu testarvuti laboriarvutini ei jõua.

## 3. Valmista laboriarvuti ette

Ava laboriarvutis tavaline PowerShell ja liigu repository juurkausta. Asenda
näidistee enda repository tegeliku teega:

```powershell
Set-Location "C:\CSA\CollectorSecurityAnalyzer"
python -m pip install -r requirements.txt
```

Määra selle testi väärtused. Asenda IP-aadressid enda aadressidega:

```powershell
$AssessmentId = "CSA-LAB-2026-07-28-01"
$LabIp = "192.168.10.20"
$TestIp = "192.168.10.31"
$Port = 8443
$PackageDir = Join-Path $PWD "collector-packages\$AssessmentId"
$PackageZip = Join-Path $PWD "collector-packages\$AssessmentId.zip"
```

Kontrolli, et port ei oleks juba kasutusel:

```powershell
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
```

Tühi tulemus tähendab, et port on vaba.

## 4. Loo assessment

```powershell
python -m csa_console.cli assessment create `
    --name "Windows 11 standard-user test" `
    --customer-reference "LOCAL-LAB" `
    --assessment-id $AssessmentId
```

Oodatav tulemus:

```json
{
  "assessmentId": "CSA-LAB-2026-07-28-01",
  "status": "OPEN"
}
```

Kui sama ID on juba kasutusel, vali uus ID. Ära kustuta vana assessment'i
ainult nime kordumise tõttu.

## 5. Ava täpselt testarvuti IP-ga seotud session

Ühe testarvuti testis kasuta võrguvahemiku asemel `--allowed-source-address`.

```powershell
$SessionInfo = (
    python -m csa_console.cli session open `
        --assessment $AssessmentId `
        --expected-devices 1 `
        --allowed-submissions 2 `
        --expires-hours 6 `
        --listen-address $LabIp `
        --port $Port `
        --allowed-source-address $TestIp |
    Out-String |
    ConvertFrom-Json
)

$SessionId = $SessionInfo.sessionId
$EnrollmentToken = $SessionInfo.enrollmentToken

$SessionInfo |
    Select-Object assessmentId, sessionId, status, expiresAt, tlsFingerprint
```

Oodatav:

- `status` on `OPEN`;
- `sessionId` algab `SES-`;
- olemas on `tlsFingerprint`;
- enrollment token kuvatakse ainult session'i loomisel.

Ära kirjuta enrollment tokenit juhendisse, logifaili, e-kirja ega chatti.
Console säilitab serveris ainult tokeni hashi, kuid Collector package sisaldab
submission'iks vajalikku tokenit ja seda tuleb käsitleda tundliku failina.

## 6. Loo ja valideeri Collector package

```powershell
$env:CSA_ENROLLMENT_TOKEN = $EnrollmentToken
try {
    python -m csa_console.cli collector-package create `
        --assessment $AssessmentId `
        --session $SessionId `
        --server-url "https://${LabIp}:$Port" `
        --output $PackageDir
}
finally {
    Remove-Item Env:\CSA_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $EnrollmentToken = $null
}

python -m csa_console.cli collector-package verify --path $PackageDir
```

`verify` peab lõppema veata ja kuvama vähemalt:

- õige assessment ID;
- õige session ID;
- `windows-standard-v1` collection profile'i;
- Collector build digesti;
- serveri sertifikaadi fingerprint'i.

Paki kataloog turvaliseks ülekandmiseks ZIP-faili:

```powershell
Compress-Archive -Path "$PackageDir\*" -DestinationPath $PackageZip
$PackageHash = (Get-FileHash $PackageZip -Algorithm SHA256).Hash
$PackageHash | Set-Content "$PackageZip.sha256.txt"
$PackageHash
```

Kopeeri testarvutisse:

```text
CSA-LAB-2026-07-28-01.zip
CSA-LAB-2026-07-28-01.zip.sha256.txt
```

Kasuta kontrollitud USB-andmekandjat või heakskiidetud read-only võrgushare'i.
Ära saada Collector package'it e-postiga.

## 7. Luba vajaduse korral laboriarvuti tulemüüris ainult testarvuti

CSA Console ei loo tulemüürireeglit automaatselt. Esmalt proovi ilma uue
reeglita. Kui Windows Defender Firewall blokeerib ühenduse, ava
laboriarvutis administraatorina PowerShell ja loo üks ajutine, täpselt
piiratud reegel.

Asenda väärtused enda omadega:

```powershell
$AssessmentId = "CSA-LAB-2026-07-28-01"
$LabIp = "192.168.10.20"
$TestIp = "192.168.10.31"
$Port = 8443
$PythonPath = (Get-Command python.exe).Source
$RuleName = "CSA-$AssessmentId-$Port"

New-NetFirewallRule `
    -DisplayName $RuleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress $LabIp `
    -LocalPort $Port `
    -RemoteAddress $TestIp `
    -Program $PythonPath `
    -Profile Any
```

See reegel on ainult laboriarvutis. Testarvuti tulemüüri ei muudeta.
Ära loo `Any` remote address'iga ega suvalise pordi reeglit.

## 8. Käivita Console laboriarvutis

Ava laboriarvutis eraldi tavaline PowerShell, liigu repository juurkausta ja
määra sama assessment ning session:

```powershell
Set-Location "C:\CSA\CollectorSecurityAnalyzer"
$AssessmentId = "CSA-LAB-2026-07-28-01"
$SessionId = "SES-PASTA-SIIA-TEGELIK-ID"

python -m csa_console.cli server start `
    --assessment $AssessmentId `
    --session $SessionId
```

Hoia see aken avatuna. Oodatav startup-info:

```text
CSA Assessment Console
listenAddress: LAB_IP
httpsPort: 8443
collectorProfile: windows-standard-v1
administrativeRightsRequiredOnEndpoints: false
activeValidation: DISABLED
```

## 9. Kontrolli testarvutist võrguühendust

Testarvutis:

```powershell
$LabIp = "192.168.10.20"
$Port = 8443
Test-NetConnection -ComputerName $LabIp -Port $Port
```

Jätka ainult siis, kui:

```text
TcpTestSucceeded : True
```

`Test-NetConnection` kontrollib ainult TCP-ühendust. Collectori päris
submission kontrollib lisaks TLS fingerprint'i, session'it, tokenit, nonce'i,
package digesteid ja source IP-d.

## 10. Valideeri ja paki Collector testarvutis lahti

Loo testarvutis ainult selle testi jaoks eraldi kataloog:

```powershell
New-Item -ItemType Directory -Path "C:\CSA-Test" -Force | Out-Null
Set-Location "C:\CSA-Test"
```

Kopeeri ZIP ja SHA-256 fail `C:\CSA-Test` kausta. Seejärel:

```powershell
$PackageZip = "C:\CSA-Test\CSA-LAB-2026-07-28-01.zip"
$ExpectedHash = (Get-Content "$PackageZip.sha256.txt" -Raw).Trim()
$ActualHash = (Get-FileHash $PackageZip -Algorithm SHA256).Hash

if ($ActualHash -ne $ExpectedHash) {
    throw "Collector package ZIP SHA-256 mismatch."
}

Expand-Archive `
    -LiteralPath $PackageZip `
    -DestinationPath "C:\CSA-Test\Collector"

Set-Location "C:\CSA-Test\Collector"
Get-ChildItem
```

Kataloogis peavad olema vähemalt:

```text
Invoke-CSACollector.ps1
session-config.json
trusted-manifest.json
server-cert.pem
offline-public.xml
collector\
```

Runner kontrollib enne kogumist iga trusted-manifest'is oleva faili digesti ja
keeldub muudetud või lisatud failidega package'it käivitamast.

## 11. Kinnita testarvuti päris tavakasutaja kontekst

Ära kasuta `Run as administrator`. Kontrolli kasutajat:

```powershell
whoami
whoami /groups
```

Local Administrators grupi SID on:

```text
S-1-5-32-544
```

Päris non-admin acceptance'i jaoks ei tohi `whoami /groups` väljundis seda
gruppi olla. Medium integrity kontroll:

```powershell
whoami /groups | Select-String "S-1-16-8192"
```

Oodatav on üks vaste. Kui kasutaja on Local Administrators grupi liige, saab
testida non-elevated ühilduvust, kuid tulemust ei tohi nimetada päris
production non-admin acceptance'iks.

## 12. Käivita Collector testarvutis

Samast tavakasutaja PowerShellist:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Invoke-CSACollector.ps1
```

`ExecutionPolicy Bypass` kehtib ainult sellele protsessile. Collector ei muuda
arvuti püsivat Execution Policy seadistust.

Oodatav väljund:

```text
Collector mode: STANDARD USER
Administrator rights required: NO
Active security testing: NO
Collection completed
Submission accepted
Receipt ID: ...
Local temporary data removed: YES
```

Acceptance'i tingimused:

- UAC dialoogi ei ilmunud;
- PowerShell käivitati medium-integrity protsessina;
- `Submission accepted` oli nähtav;
- receipt ID oli olemas;
- temporary cleanup oli `YES`;
- endpointi registrit, tulemüüri, teenuseid ega scheduled task'e ei muudetud.

Pärast edukat jooksu võib kontrollida:

```powershell
Get-ChildItem "$env:TEMP\CSA" -Force -ErrorAction SilentlyContinue
```

Uue submission ID-ga temp-kataloogi ei tohi alles olla.

## 13. Kontrolli submission'it laboriarvutis

Jäta serveriaken tööle ja ava laboriarvutis teine PowerShell:

```powershell
Set-Location "C:\CSA\CollectorSecurityAnalyzer"
$AssessmentId = "CSA-LAB-2026-07-28-01"

python -m csa_console.cli assessment status --assessment $AssessmentId

$SubmissionList = (
    python -m csa_console.cli submission list `
        --assessment $AssessmentId |
    Out-String |
    ConvertFrom-Json
)

$SubmissionList.items |
    Format-Table submissionId, deviceId, state, receivedAt, transport
```

Oodatav:

```text
acceptedSubmissions: 1
state: EVIDENCE_ACCEPTED
transport: HTTPS
```

Salvesta submission ID järgmiste käskude jaoks:

```powershell
$SubmissionId = (
    $SubmissionList.items |
    Sort-Object receivedAt -Descending |
    Select-Object -First 1
).submissionId

$SubmissionId
```

Kontrolli privilege context'i canonical evidence'ist:

```powershell
$NormalizedPath = Join-Path $PWD `
    "assessments\$AssessmentId\normalized\$SubmissionId.json"
$Normalized = Get-Content -Raw -LiteralPath $NormalizedPath | ConvertFrom-Json
$Normalized.privilegeContext | Format-List
```

Päris tavakasutaja korral peab tulemus sisaldama:

```text
executionMode              STANDARD_USER
isElevated                 False
isLocalAdministratorMember False
integrityLevel             MEDIUM
```

## 14. Genereeri ja ava raportid laboriarvutis

Endpoint analüüs ja endpoint report käivituvad vaikimisi automaatselt pärast
submission'i vastuvõtmist. Fleet-koondi ja kõigi raportite värskendamiseks:

```powershell
python -m csa_console.cli analyze fleet --assessment $AssessmentId
python -m csa_console.cli report generate-all --assessment $AssessmentId
```

Raportid asuvad:

```text
assessments\<ASSESSMENT-ID>\reports\
    endpoints\<SUBMISSION-ID>.console.html
    endpoints\style.css
    fleet\fleet-technical.html
    fleet\dashboard.html
    fleet\style.css
    executive\executive.html
    executive\style.css
```

Ava raportid:

```powershell
$ReportRoot = Join-Path $PWD "assessments\$AssessmentId\reports"

Start-Process (
    Join-Path $ReportRoot "endpoints\$SubmissionId.console.html"
)
Start-Process (
    Join-Path $ReportRoot "fleet\fleet-technical.html"
)
Start-Process (
    Join-Path $ReportRoot "fleet\dashboard.html"
)
Start-Process (
    Join-Path $ReportRoot "executive\executive.html"
)
```

Kui raporteid on vaja teise turvalisse asukohta kopeerida, kopeeri terve
`reports` kataloog. Ära kopeeri ainult HTML-faili, sest CSS asub sama
raportitüübi alamkaustas.

Raportid võivad sisaldada tundlikku konfiguratsiooni. Hoia neid krüpteeritud
laborikettal või heakskiidetud krüpteeritud andmekandjal.

## 15. Kui online-submission ei ole võimalik

Collector package toetab krüpteeritud offline-exporti. Testarvutis:

```powershell
New-Item -ItemType Directory -Path "C:\CSA-Test\Offline" -Force | Out-Null

powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\Invoke-CSACollector.ps1 `
    -NoSubmit `
    -ExportPath "C:\CSA-Test\Offline"
```

Oodatav:

```text
Encrypted offline submission created: ...\SUB-....csa
Local temporary data removed: YES
```

Kopeeri ainult `.csa` fail turvaliselt laboriarvutisse ja impordi see enne
session'i sulgemist:

```powershell
python -m csa_console.cli submission import `
    --assessment $AssessmentId `
    --file "E:\CSA-Drop\SUB-....csa"

python -m csa_console.cli analyze fleet --assessment $AssessmentId
python -m csa_console.cli report generate-all --assessment $AssessmentId
```

Offline-fail on krüpteeritud session'i avaliku võtmega. Sama faili teine import
peab andma duplicate/replay vea.

## 16. Levinud vead

### `TcpTestSucceeded : False`

Kontrolli:

1. kas Console'i serveriaken töötab;
2. kas package'i `serverUrl` kasutab õiget laboriarvuti IP-d;
3. kas port 8443 on õige;
4. kas laboriarvuti tulemüürireegel lubab ainult testarvuti tegelikku IP-d;
5. kas VPN või teine adapter suunab liiklust vale liidese kaudu.

### `SERVER_IDENTITY_VALIDATION_FAILED`

Ära keela TLS-kontrolli. Loo õige session'i ja õige labori-IP-ga uus Collector
package. Kontrolli ka mõlema arvuti kellaaega.

### `REJECTED_UNAUTHORIZED_SOURCE`

Testarvuti source IP ei vasta session'i `allowedSourceAddresses` väärtusele.
DHCP võis aadressi muuta. Ava uus session või kasuta uut package'it, mille
source-scope vastab tegelikule aadressile.

### `Collector package has expired`

Package on seotud aegunud session'iga. Loo uus session ja uus package. Ära
muuda `session-config.json` faili käsitsi.

### `STANDARD_USER_COLLECTION refuses an elevated or SYSTEM process`

Sulge administraatorina avatud terminal ja käivita Collector tavalisest
PowerShellist.

### Submission on vastu võetud, kuid endpoint report puudub

```powershell
python -m csa_console.cli submission retry-analysis `
    --assessment $AssessmentId `
    --submission $SubmissionId

python -m csa_console.cli report endpoint `
    --assessment $AssessmentId `
    --submission $SubmissionId
```

## 17. Kontrolli auditit enne lõpetamist

Enne serveri ja session'i sulgemist kontrolli, et senine auditiahel on terve:

```powershell
python -m csa_console.cli assessment verify --assessment $AssessmentId
```

Oodatav:

```text
auditVerificationStatus: VERIFIED
finalAuditEntryHash: sha256:...
```

## 18. Sulge test turvaliselt

Peata server laboriarvuti teisest PowerShellist:

```powershell
python -m csa_console.cli server stop `
    --assessment $AssessmentId `
    --session $SessionId
```

Sulge session ja assessment:

```powershell
python -m csa_console.cli session close `
    --assessment $AssessmentId `
    --session $SessionId

python -m csa_console.cli assessment close `
    --assessment $AssessmentId
```

Kontrolli nüüd lõplikku auditiahelat:

```powershell
python -m csa_console.cli assessment verify --assessment $AssessmentId
```

Ekspordi suletud assessment koos lõpetamise auditisündmustega krüpteeritud
arhiivina:

```powershell
python -m csa_console.cli assessment export `
    --assessment $AssessmentId `
    --output ".\$AssessmentId.csa" `
    --encrypt
```

Parool küsitakse secure prompt'is. Seda ei anta command line'il ega salvestata
konfiguratsiooni.

Kontrolli arhiivi:

```powershell
python -m csa_console.cli assessment verify `
    --file ".\$AssessmentId.csa"
```

Kui lõid laboriarvutisse ajutise tulemüürireegli, eemalda see administraatorina
avatud PowerShellist:

```powershell
Remove-NetFirewallRule -DisplayName "CSA-$AssessmentId-$Port"
```

Kontrolli, et reeglit ja listenerit enam ei ole:

```powershell
Get-NetFirewallRule -DisplayName "CSA-$AssessmentId-$Port" `
    -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort $Port -State Listen `
    -ErrorAction SilentlyContinue
```

Mõlemad käsud peavad andma tühja tulemuse.

Pärast aktsepteeritud submission'it ja raportite kontrollimist eemalda
testarvutist spetsiaalselt loodud `C:\CSA-Test` kataloog. Laboriarvutis eemalda
levitamiseks loodud Collector ZIP ja package pärast session'i sulgemist.
Assessment evidence ja raportid säilita retention-policy järgi.

## 19. Testiprotokoll

Salvesta acceptance-protokolli vähemalt:

```text
Assessment ID:
Session ID:
Laboriarvuti IP:
Testarvuti IP:
Testarvuti Windows build:
Testkasutaja Local Administrators liige: NO
Integrity level: MEDIUM
UAC prompt: NO
Submission accepted: YES
Receipt ID:
Temporary cleanup: YES
Endpoint changes: NONE
Active Validation: NOT PERFORMED
Endpoint report: GENERATED
Fleet report: GENERATED
Executive report: GENERATED
Audit verification: VERIFIED
Final audit hash:
Firewall rule removed: YES / NOT CREATED
Testarvuti temp-kataloog eemaldatud: YES
```

Sprint 5.0 production non-admin acceptance on täidetud ainult siis, kui
testkasutaja ei kuulu Local Administrators gruppi, protsess on medium-integrity,
UAC dialoogi ei teki ja online- või krüpteeritud offline-submission jõuab
Console'is valideeritud evidence'i ning raportini.
