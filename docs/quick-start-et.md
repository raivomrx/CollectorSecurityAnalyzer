# CSA Lab kiirjuhend

**5.6.8.2 arenduskandidaat: UNSIGNED LAB ONLY. Avalik väljalase HOLD.**
Kinnitatud privaatse kliendipiloodi EXE ja Quick Runi töövoog on
[5.6.8.2 hindaja kiirjuhendis](sprint-5.6.8.2-client-pilot.md).
See töötab sõltumatu privaatse üleandmisega ilma tootmise sertifikaadi ja
Collectori eelpaigalduseta. Allolev varasem juhend käsitleb tootmise
eelpaigaldatud võrgu-Copy töövoogu.
ADR 565 arendus on kinnitatud, kuid avaldaja sertifikaat, võtmeomanik ja
sõltumatu usalduskanal on veel kinnitamata (`TRUST_ENROLLMENT_PENDING`).
Tavaline Copy ja **Quick Run – ExecutionPolicy Bypass** jäävad keelatuks kuni
sõltumatu usalduse juurutamiseni. Arenduskandidaadi enda SHA-256 või sertifikaat
ei tõesta sõltumatut usaldust. Kliendipiloot vajab eraldi vastuvõttu.

[Levituse, seadistuse ja vastuvõtu juhend](sprint-5.6.8.1-correction.md)

[PowerShell Copy & Paste eelvaade ja usaldusnõuded](sprint-5.6.5-quick-start.md#eesti-keeles)

1. Ava laboriarvutis **CSA Lab**.
2. Vajuta **New Assessment**.
3. Sisesta nimi ja testarvutite arv.
4. Kinnita õige Private või Domain võrguliides.
5. Vajuta **Create Assessment** ja seejärel **Start Collection**.
6. Kinnita laboriarvutis Windows Firewalli UAC dialoog.
7. Vajuta aktiivses assessment'is **Copy Collector Page**.
8. Sulge testarvutis varasem CSA sakk ja kleebi kogu uus aadress brauseri
   aadressiribale. Igal assessment'il on erinev ja aeguv join URL.
9. Kontrolli hindajaga sõltumatu kinnitatud kanali kaudu Labi täpset aadressi ja
   TLS-identiteeti. Lehel endal kuvatud sõrmejälg üksi ei tõenda lehe päritolu.
   Lahendamata brauserihoiatuse korral kasuta kinnitatud eraldi üleandmist.
10. Vali pärast sõltumatu usalduse kinnitamist tavaline PowerShelli Copy
    või **Quick Run – ExecutionPolicy Bypass** ja kleebi käsk üks kord
    tavakasutaja Windows PowerShelli. Sisesta eraldi antud ühekordne kood
    alles paigaldatud käivitaja peidetud sisestusviibal. HOLD-olekus küsi
    hindajalt sõltumatult kinnitatud üleandmist. Allkirjastamata allalaadimine
    on lubatud ainult selgelt märgitud sisemises hindaja arendusrežiimis.
11. Oota teadet **Submission accepted**.
12. Kontrolli CSA Labis, et endpoint on **Complete**, transport on **HTTPS**,
    execution mode on standard user ja integrity on medium.
13. Vajuta pärast viimast endpointi **Stop Collection**.
14. Vajuta **Generate Assessment Report** ja seejärel **Open Report**.
15. Vajadusel vali **Export Assessment Archive** ning kasuta vähemalt
    12-märgilist tugevat parooli.

`CLOSED` ja `COMPLETED` assessment'i saab nupuga **Delete Assessment**
pöördumatult kustutada. See eemaldab kohalikud evidence-, report- ja
assessment'i auditifailid. Rakenduse üldisesse auditilogisse jääb kustutamise
kinnitus koos assessment'i auditiahela lõpphashiga.

Kui võrguühendus ei tööta, vali Collectoris encrypted offline package ning
impordi `.csa` fail CSA Labi nupuga **Import Offline Package**. Seda saab teha ka
pärast **Stop Collection** valimist, kuni assessment'i session expiry pole
möödunud. Pärast uue endpointi importi genereeri unified raport uuesti.

Ettevõtte hallatud Windowsis kasutab usaldatud töövoog IT poolt juurutatud,
allkirjastatud muutumatut käivitajat ja sõltumatult üle antud Labi usaldusandmeid.
Windows Home'is tuleb samad identiteedid hindajaga eraldi kontrollida ja
usalduspakett volitatud viisil paigaldada. Collector ise UAC-d ei küsi ega
usalduse seadistust ei muuda. Kui PowerShelli või rakenduse käivitamine on
reeglitega keelatud, palu IT heakskiidetud allkirjastatud või offline-töövoogu.
Quick Run kasutab ainult Collectori käivituse protsessipoliitikat. See ei
muuda arvuti püsivat poliitikat, ei tühista GPO-d ja jätab Defenderi, AMSI,
WDAC-i ning AppLockeri aktiivseks.

Pärast tegelikku usalduse juurutamist saab privaatse sessioonipaketi käivitada
paigaldatud `CSA-TrustedCollector.exe --bundle <kaust>` või samas kaustas oleva
`Start-CSATrustedCollector.ps1 -Bundle <kaust>` kaudu. Käsk ja pakett tuleb
saada sõltumatu kinnitatud kanali kaudu. Offline-eksport vajab lisaks
`--offline <väljund.csa>` (EXE) või `-OfflineExport <väljund.csa>` (PowerShell).
Usalduse, värske tühistusinfo või sessiooni aegumise kontrolli nurjumisel
kogumine peatub; uut luba küsitakse hindajalt. Ühekordset luba ei lähtestata.

Windowsi hoiatuse korral salvesta lubatud kohalikku diagnostikasse faili
SHA-256, allkirja olek, täpne kellaaeg ja Protection History tuvastuse nimi/tegevus
või Defenderi sündmuse 1116/1117 viide. SmartScreeni mainehoiatus ning
Smart App Controli/WDAC/AppLockeri keeld on eraldi juhtumid. Allkiri ei taga
mainehoiatuse puudumist. Portaali vea korral anna hindajale `CSA-PORTAL-ERROR`
ja korrelatsiooniviide, kontrolli aktiivset assessment'i ning kasuta uut lehte.
Ära jaga join-linki, sessioonipaketti või toorandmeid avalikes veateadetes.
