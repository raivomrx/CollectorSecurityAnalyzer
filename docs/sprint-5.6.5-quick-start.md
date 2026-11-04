# CSA 5.6.5 · PowerShell Quick Start

## English

The Join page shows **PowerShell Copy & Paste — one command** with
`TRUST_NOT_ESTABLISHED` and a disabled **Copy command** button. This preview
provides no command. The planned flow runs once as the current standard user,
downloads to temporary storage, submits to the enrolled Lab and cleans up.
It requires independently verified publisher, Lab and command origins.

For an approved LAB assessment, use **CSA Collector (.exe)** or the existing
**Download PowerShell Quick Start (.ps1)**. For the latter, save
`Start-CSACollector.ps1`, open Windows PowerShell in the download folder and
use the local-file command displayed by the Join page.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-CSACollector.ps1
```

The command applies `Bypass` to its process. Effective Group Policy and Windows
application control still apply. For a Windows policy block, record the
diagnostic and ask the assessor for an approved signed or offline workflow.
The **PowerShell Offline Package (.zip)** remains available for explicit
encrypted offline export. The existing downloads are scoped to the session.
Their integrity checks have the documented COL-1 trust limit.

Before a future one-command pilot, provision the publisher verifier and Lab
trust record independently. Use an organization-authenticated Join page or
obtain the command through the authenticated assessor channel. For self-signed
Lab TLS, independently match the full SHA-256 certificate fingerprint with the
assessor's own Lab display and verify the Lab signing key. A matching address
or a fingerprint shown by the received Join page cannot establish first contact.
Confirm a server-validated submission and cleanup on LAB and HOME. The public
release remains HOLD. [ADR 565](ADR-565-col1-copy-paste.md)

## Eesti keeles

Liitumislehel on **PowerShell Copy & Paste — one command** eelvaade. Olek
`TRUST_NOT_ESTABLISHED` ja keelatud **Copy command** nupp tähendavad, et käsku
saab pakkuda pärast väljaandja, Labi ja käsu päritolu sõltumatut kinnitamist.
Kavandatud käivitus töötab üks kord tavakasutajana, laadib kogumismootori
ajutisse kausta, esitab tõendi registreeritud Labile ja koristab ajutised failid.

Kinnitatud LAB-i hindamiseks kasuta **CSA Collector (.exe)** või olemasolevat
valikut **Download PowerShell Quick Start (.ps1)**. Salvesta
`Start-CSACollector.ps1`, ava allalaadimiskaustas tavakasutajana Windows
PowerShell ning kasuta liitumislehel kuvatavat kohaliku faili käsku.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-CSACollector.ps1
```

`Bypass` kehtib sellele protsessile. Organisatsiooni rühmapoliitika ja Windowsi
rakenduskontroll kehtivad edasi. Tõkestuse korral salvesta Windowsi teade ja
küsi hindajalt kinnitatud allkirjastatud või võrguühenduseta töövoogu. **PowerShell
Offline Package (.zip)** sobib krüpteeritud võrguühenduseta ekspordiks.

Ühe käsu piloodi eel paigalda sõltumatult kinnitatud väljaandja käiviti ja Labi
usalduskirje. Hangi käsk organisatsiooni kinnitatud liitumislehelt või hindaja
autenditud kanalist. Iseallkirjastatud TLS-i korral võrdle sertifikaadi täielikku
SHA-256 sõrmejälge hindaja enda Labi kuval oleva väärtusega ja kinnita ka Labi
allkirjastamisvõti. Päristestis kontrolli mõlemal arvutil, et Lab võttis
esituse vastu ja ajutised failid eemaldati. Avalik väljalase on ootel.
[Arhitektuuriotsus](ADR-565-col1-copy-paste.md)
