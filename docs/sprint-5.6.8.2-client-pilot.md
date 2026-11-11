# CSA 5.6.8.2 — hindaja kinnitatud kliendipiloot

Projektijuht kinnitas ADR 5682 erandi 11.11.2026. Kliendi kasutusluba on
olemas. Privaatne `ASSESSOR_VERIFIED_PILOT` ei nõua tootmise
koodiallkirjastamissertifikaati, administraatoriõigusi, sertifikaadihoidla
muutmist ega Collectori eelpaigaldust. Avalik väljalase on endiselt HOLD.
Windowsi kaitsed võivad käivitamisest keelduda; neid ei lülitata välja.

## Hindaja kiirstart

1. Paigalda selle commiti CSA Lab arendusinstaller hindaja arvutisse.
   Kontrolli GitHubi ehituse räsi sõltumatu heakskiidetud allika kaudu.
   Loo uus assessment õige kliendivõrgu, profiili ja kehtivusajaga ning
   käivita Collection. Lab-i võrguühenduse tulemüürireegel võib nõuda
   hindaja arvutis eraldi administraatori kinnitust; Collector seda ei küsi.
2. Ava **Settings → Distribution → Hindaja kinnitatud privaatne piloot**.
   Sisesta saaja tunnus (16–128 ladina tähte/numbrit, alakriips või sidekriips,
   näiteks `CLIENT-PILOT-00000001`), hindaja, kliendi lepingu/loa viide,
   hindaja kinnitus ning sõltumatu üleandmiskanali viide.
3. Käivita kliendiarvuti tavalises Windows PowerShellis samas vaates antud
   lugemiskäsk arvuti sõrmejälje saamiseks. Käsk loeb MachineGuid väärtuse
   ja väljastab ainult SHA-256; toorväärtust ei lisata paketti ega logisse.
   Sisesta sõrmejälg ja kliendiarvuti täpne lähteaadress. Kontrolli neid
   kliendiga kohapeal või kinnitatud sõltumatu kanali kaudu.
4. Kinnita selle arvuti piiratud piloodi risk ja vajuta
   **Koosta privaatne piloodipakett**. Lab loob kaks eri RSA-3072
   ajutist allkirjastajat mälus, allkirjastab muutumatu väljalaske ja
   sessiooni manifestid ning registreerib ühekordse loa. Privaatvõtmeid
   ei salvestata ega ekspordita. Kehtivus on kuni kaks tundi ja alati
   sessiooni piires. Loa, allkirjastajate ja TLS-i avalikud identiteedid
   seotakse `pilot-approval.json` täpse räsiga.
5. Vajuta **Salvesta privaatne ZIP** ja anna pakett kliendile kinnitatud
   privaatse kanali kaudu. See sisaldab lühiajalisi sessiooniandmeid:
   ära pane seda avalikku veebi, GitHubi, avalikku failijagamisse ega logisse.
   Võrdle **approval SHA-256 ja EXE SHA-256 sõltumatult** hindaja Lab-i
   ekraani või eraldi kinnitatud kirje kaudu. ZIP-i enda räside loetelu
   üksi ei tõenda paketi päritolu.
6. Paki ZIP kliendiarvutis eraldi kausta, näiteks `C:\CSA-Pilot`.
   Sisesta tegelik kaust Lab-i väljale **ZIP-i lahtipakkimise kaust
   kliendiarvutis** ning vajuta **Kuva EXE ja Copy & Paste käsud**.
   Kasuta kuvatud tegelikke käske, milles on selle üleandmise avalikud
   räsiandmed. Käsus ei ole enrollment-tokenit, sessiooni nonce'i,
   parooli ega privaatvõtit.

## Kliendiarvutis: EXE või Quick Run

- **EXE:** pärast sõltumatut sõrmejälgede võrdlemist käivita kuvatud EXE
  käsk tavalises CMD aknas. See käivitab muutumatu
  `CSA-TrustedCollector.exe --assessor-pilot` samast privaatsest kaustast.
  Allkirjastatud EXE-le ei lisata kliendipõhist overlay'd. Käivitaja
  kontrollib enda ja PS-artifakti täpseid baite kinnitatud manifesti vastu.
- **Quick Run:** vajuta **Kopeeri Quick Run**, kleebi kogu käsk tavalisse
  Windows PowerShelli või CMD-sse ning käivita. Kasutatakse üksnes
  protsessipõhist `-ExecutionPolicy Bypass`. Käsk hoiab EXE-d
  kirjutamist/asendamist keelava lugemislingiga, kontrollib sõltumatult
  saadud EXE räsi ja käivitab siis sama kontrollija. Sama funktsiooni
  tavalise täitmispoliitikaga käsk on samuti valitava tekstina nähtav.
- Mõlemad kontrollivad sõltumatult kinnitatud approval-faili räsi,
  CMS-allkirju, võtmerolle, sessiooni, profiili, TLS-i sõrmejälge,
  arvuti sõrmejälge, kehtivust, paketi terviklust ja korduskasutust.
  Privaatne ajutine allkirjastaja ei muutu Windowsi usaldatud Publisheriks.
  Raportis on `ASSESSOR_VERIFIED_PILOT`, mitte tootmise allkirja
  `VERIFIED` ega `TEST_ONLY`.
- Vaata Collectori verify/collect/submit/cleanup teateid ning
  **Submission accepted** kinnitust. Lab-is peab tõendil olema õige profiil,
  privaatsuskontroll ja allkirjastatud vastuvõtukviitung. Sama pakett
  lubab ühe käivituse; EXE ja Quick Runi eraldi katseks loo kaks paketti.
- Eduka käivituse järel eemaldatakse ajutine mootor ja kliendikausta
  privaatsed sessioonifailid. Kustuta ülejäänud üleandmiskoopia ja ZIP.
  Katkestuse korral palu hindajal seisund üle vaadata, privaatne koopia
  eemaldada ning vajadusel väljastada uus luba. Tarbitud luba ei lähtestata.

Võrguta kogumiseks lisa EXE käsule `--offline <väljund.csa>`.
See kasutab sama profiili ja krüpteeritud offline-vormingut. Impordi fail
hindaja Lab-is **Import Offline Package** kaudu kehtiva sessiooni jooksul
ja kontrolli kviitungit. Avalikku bootstrap-download'i ega legacy
allalaadimisi see piloot ei ava.

## Kui käivitamine või edastus ei õnnestu

Kasuta tavakasutaja akent, mitte **Run as administrator**.
Vale arvuti, räsi, sessioon, lähteaadress, aegumine või korduskasutus
peatab jooksu. Windowsi GPO, Defenderi, Smart App Controli, WDAC-i,
AppLockeri või AMSI keelu korral salvesta täpne veakood, UTC aeg ja
kaitse sündmuse nimi/ID. Portaali veal lisa correlation ID ja stage.
Ära saada toortõendit, tokenit ega privaatset paketti diagnostikalogisse.
Ära lülita kaitset välja ega muuda CurrentUser/LocalMachine poliitikat.

## PILOT_GO_NO_GO

| Tee | Tehniline valmisolek | Kasutuse tingimus |
|---|---|---|
| Privaatne EXE | Hindaja koostatud ja kontrollitud üleandmine | Arvuti/loa viited, sõltumatult võrreldud räsi, kehtiv sessioon; Windows lubab käivitust |
| Privaatne Quick Run | Sama pakett ja mootor, protsessipõhine Bypass | Samad tingimused; kohaliku kausta käsk hindaja kinnitatud allikast |
| Avalik võrgu-Copy / tootmise Publisher | TRUST_ENROLLMENT_PENDING | Tootmise identiteedid ja juurutus vajavad eraldi kinnitust |
| Legacy / DEVELOPMENT_UNSIGNED | Kliendipiloodis ei kasutata | Ei avane piloodi ega usaldusvea kõrvalmõjuna |
| Avalik release | HOLD | Arhitekti ja projektijuhi eraldi vastuvõtt |

Sünteetiline Windowsi regressioon ei tõenda päris HOME/LAB või kliendiarvuti
vastuvõttu. Säilita sama muutumatu kandidaadi päris katsel OS/PowerShell,
tavakasutaja õigused, kaitse olek, sõltumatu üleandmise kinnitus,
täpsed binaariräsid, kviitung, võrreldav profiil/privaatsus ja koristus.
Kliendikeskkonna toimivust saab kinnitada alles selle reaalse katse põhjal.

Rakendus: `AssessorPilot.cs`, `assessor_pilot.py`, kohalik Lab-i UI/API,
ühekordse loa lähteaadressi/aegumise kontroll ning eraldi kaitstud
päritolukviitung. Testid: `test_assessor_pilot`, `test_pilot_readiness`,
olemasolevad usaldus-, raporti-, privaatsus- ja Pesteri regressioonid.
