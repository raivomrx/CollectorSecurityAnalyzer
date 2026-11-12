# CSA 5.6.8.3 — Joini klienditeekond ja vastuvõtt

Baseline: 5.6.8.2 / fa88028. Avalik väljalase: HOLD. Kinnitatud ADR 5682
privaatne piloot on sellest eraldi. Päris HOME/LAB vastuvõtu kinnitab
projektijuht pärast sama kandidaadi live-katseid.

## Hindaja: ettevalmistusest käivitusloani

1. Loo assessment õige võrgu, profiili ja kehtivusega ning käivita
   **Start Collection**. Ava **Settings → Distribution**.
2. Koosta privaatne piloodipakett senise ADR 5682 voo abil: saaja tunnus,
   arvuti sõrmejälg, täpne lähteaadress ning hindaja/kliendi/kanali
   kinnitused. See lõpetab ainult sammu **PACKAGE_PREPARED**.
3. Võrdle approval- ja EXE-räsi sõltumatu kinnitatud kanali kaudu.
   Sisesta tegelikult kontrollitud väärtused ja kontrolli viide ning
   vajuta **Kinnita sõltumatu kontroll**. Lab kontrollib täpseid
   tarnebaite sama native-verifieriga ning fikseerib muutumatu arhiivi,
   kontrollskripti räsi ja auditiviite. Seisund:
   **INDEPENDENT_HANDOFF_VERIFIED**.
4. Sisesta käivitusloa viide ja vajuta **Luba käivitus Join-lehelt**.
   Seisund: **AUTHORIZED_FOR_EXECUTION**. Lab väljastab ühe korra
   privaatselt edastatava koodi; andmebaasi jääb ainult selle räsi.
   Anna kliendile assessmenti **Copy Collector Page** aadress ja
   kood eraldi kinnitatud kanali kaudu. Kontrolli koos kliendiga
   ka Joini päritolu ja Lab-i TLS-identiteeti. Leht ei kinnita ise
   oma usaldusankrut.
5. Jälgi samas vaates **EXECUTION_STARTED** ja **EVIDENCE_RECEIVED**.
   Viimane nõuab tegelikku allkirjastatud vastuvõtukviitungit,
   mitte allalaadimist ega brauserinupu vajutamist.
6. Peata kogumine ja genereeri HTML-raport. CVE analüüsi senised
   täielikkuse piirid ja vajadusel selgesõnaline puuduliku analüüsi
   kinnitus jäävad kehtima. Pärast projektijuhi päris live-katset
   märgi **Kinnita live-vastuvõtt** koos tõendi viitega.
   **ACCEPTANCE_COMPLETED** ei teki automaattesti ega CI tõttu.

Kaotatud või tarbitud koodi ei taastata. Tühista vana luba ja koosta uus
üleandmine. Mõlema meetodi võrdluskatses kasuta kahte eri ühekordset luba
samale arvutile; kogumismootor ja privaatsusprofiil on samad.

## Klient: üks lühike Join-leht

Klient sisestab hindajalt saadud koodi. Seejärel näeb ta:

- **PowerShell Quick Run**: kopeeri käsk Windows PowerShelli ja sisesta
  hindaja kood turvalisel sisestusviibal. Allalaadimine, kontroll,
  lahtipakkimine, native Collectori käivitus ja ajutiste failide
  koristamine toimuvad automaatselt. Tavaline PowerShell on lisavalik.
- **Windows EXE Collector**: laadi alla privaatne EXE pakett ZIP-vormingus,
  paki lahti ja ava **Start-CSACollector.cmd**. See käivitab sama
  muutumatu EXE-kontrollija. EXE ei saa kliendipõhist overlay'd ega vaja
  paigaldust. ZIP on vajalik sessiooniandmete hoidmiseks EXE-st eraldi;
  seda ei esitata üksikfaililise EXE allalaadimisena.

Quick Runi käsk on kopeeritav ka siis, kui selle pikk tekst on peidetud.
Lõikelaua loa puudumisel avaneb valitav käsutekst. Kui ühtegi meetodit
ei ole lubatud või luba on aegunud, on lehel ainult lühike suunamine
hindaja poole. Sisemised trust/release/seadistusolekud ja pikad
konfiguratsioonijuhised jäävad hindaja Lab-i ning auditisse.

## Säilinud turvapiirid ja tarneprotokoll

Selle integratsiooniga ei lisata usaldusjuurt, allkirjastajat ega uut
krüptoalgoritmi. Autoriteet on endiselt ADR 5682 sõltumatult kontrollitud
approval/EXE identiteet, eraldi allkirjastatud avaldaja- ja Lab-manifest,
täpne arvuti, sessioon/profiil, TLS-pin, aegumine ja ühekordne kogumisluba.

Joini lisakood/cookie/ticket on üksnes privaatse tarne autoriseerimiseks.
Kood liigub maskitud vormi või turvalise terminalisisendi ja TLS-i
Authorization päise kaudu; see ei ole URL-is, käsureal, kopeeritud käsus,
shell-history's, raportis ega logis. Cookie on Secure/HttpOnly/SameSite=Strict.
Allalaadimispilet kehtib kuni 120 sekundit ja lubab kõige rohkem kolm
katset. Koodi korduskasutus uue pileti saamiseks, vale lähteaadress,
kasutatud/aegunud kogumisluba või muudetud pakett keeldutakse.

Quick Runi lühike avalikke pinne sisaldav käsk laadib kõigepealt fikseeritud
transpordi-kontrollija, kontrollib selle räsi ja hoiab kontrollitud faili
kirjutamist keelava lugemislingiga käivituse lõpuni. Alles seejärel
hangitakse koodi abil privaatne arhiiv. Arhiivi täpne räsi, turvalised
failinimed, piiratud suurus, EXE täpsed baidid ning native kontrolli
CMS/sessiooni/arvuti/profiili kontrollid eelnevad kogumisele.
IEX-i ega kontrollimata kaugkoodi täitmist ei kasutata.

Ainult klassifitseeritud katkenud võrgusiire lubab piiratud korduskatset.
Vale TLS, täieliku faili vale räsi, allkirja- või usaldusviga ei kordu.
EXE ja Quick Run võivad mõlemad küsida lapseprotsessile Bypass'i; nende
**transpordiliik** salvestatakse eraldi (`EXE` vs
`QUICK_RUN_PROCESS_BYPASS`). Tavaline PowerShell säilitab protsessipoliitika.
Need on kliendi raporteeritud käivitusandmed, mitte kaugattestatsioon.
GPO, Defender, AMSI, WDAC, AppLocker ja Smart App Control jäävad jõusse.

## AP-01…AP-04 ja elutsükkel

- AP-01: EXE käsule ei lisata enam Quick Runi lippu; transport on
  native väljundis, kaitstud kviitungis ja Lab-i edenemises eristatav.
- AP-02: koostatud pakett ei tähenda kontrollitud üleandmist,
  käivitusluba ega live-vastuvõttu. Iga etapp on eraldi.
- AP-03: loobutud/aegunud/tühistatud ja vastu võetud pakettide privaatne
  sessiooniarhiiv eemaldatakse Lab-is. Katkenud väljastuse järel koristatakse
  failid; faililuku korral jääb koristus ootele ning järgmine värskendus
  proovib uuesti. Tarbitud märgiseid ja ajaloolist päritolukviitungit
  ei lähtestata. Quick Run koristab oma piiratud ajutise kausta ka vea korral.
  EXE meetodi algne brauseri ZIP jääb kliendi kustutada; leht ütleb seda.
- AP-04: native/Win32/PowerShelli integratsioonitestid on Windowsi-põhised.
  Windowsi testides ei jäeta neid vahele. Kõrgendatud õigustega CI-runner
  kasutab sünteetilise tokeni fixture'it; tootmise õiguste keeld jääb alles
  ja selle toimimist kontrollitakse eraldi. Kohalik tavakasutaja katse
  käivitab päris muutumatu EXE.

## Vastuvõtutõend

`tests/test_join_journey.py` kontrollib tegelikku HTTPS Joini aktiveerimist,
privaatset EXE allalaadimist, kasutajale kuvatud kopeerimiskäsu kogu
allalaadimis-/kontrolli-/käivitusvoogu, sama sünteetilise tõendi
privaatsust ja profiili, allkirjastatud kviitungeid, HTML-raportit,
allalaadimise katkemist, vale TLS-i, muudetud kontrollijat/arhiivi,
ühekordsust, aegumist, tühistamist ja koristuse korduskatset.
Terminalisisend on automaattestis asendatud sünteetilise turvasisendi
fixture'iga; tootmiskoodis sisendi ega usalduse bypass-lippu ei ole.

Brauseritest lisab päris Joini ekraanipildi ja kontrollib, et leht on
lühike ning Copy ei sisalda privaatselt saadud koodi. See brauseritest
ei asenda native kogumise teekonnatesti ega päris HOME/LAB vastuvõttu.

Projektijuhi live-katse: sama kandidaadiga HOME ja LAB, kaitsed aktiivsed,
tavakasutaja õigused, mõlemad meetodid eraldi loaga, Lab-is töödeldud
võrdväärne tõend, kviitung ja HTML-raport. Need katsed on veel **PENDING**.
Avalik väljalase jääb **HOLD**.
