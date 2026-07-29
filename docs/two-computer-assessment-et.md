# Kahe Windows 11 arvuti assessment

## Eeldused

- laboriarvutis on CSA Lab;
- testarvuti kasutaja ei kuulu Local Administrators gruppi;
- mõlemad arvutid on samas LAN-is;
- laboriarvuti valitud LAN-i võrguprofiil on Private või Domain;
- testarvutis ei avata Collectorit administraatorina.

## 1. Assessment laboriarvutis

1. Ava CSA Lab ja vali **New Assessment**.
2. Sisesta assessment'i nimi ning `Expected endpoints: 1`.
3. Vali loendist labori LAN-adapter. Kontrolli kuvatud IP-d ja subnetti.
4. Loo assessment.
5. Vajuta **Start Collection**.
6. Kinnita UAC ainult laboriarvutis. Reegel peab olema nimega
   `CSA Lab Temporary ...` ning piiratud valitud pordi, kohaliku IP, profiili,
   programmi ja source subnetiga.
7. Jäta CSA Lab avatuks ja kopeeri kuvatud Collector page aadress.

## 2. Collector testarvutis

1. Logi testarvutisse tavakasutajana.
2. Ava brauseris laboriarvuti antud HTTPS-aadress.
3. Kui brauser hoiatab generated certificate'i eest, võrdle URL-i IP-d CSA
   Labi ekraaniga. Ära jätka tundmatu aadressiga.
4. Vajuta **Download CSA Collector**.
5. Käivita `CSA-Collector.exe` tavaliselt. Ära vali **Run as administrator**.
6. Kontrolli Collectori tekstist:
   - `Mode: Standard User`;
   - `Administrator rights required: NO`;
   - õige assessment ja server.
7. Oota samme integrity check, collection, privacy validation, HTTPS send,
   receipt ja cleanup.
8. Edu korral kuvatakse **Evidence accepted by CSA Lab** ning receipt ID.

Collector ei paigalda agenti, teenust ega scheduled task'i, ei muuda registrit
ega endpointi tulemüüri ning eemaldab oma ajutised failid.

## 3. Kontroll laboriarvutis

Endpoint peab ilmuma tabelisse:

- Status: `COMPLETE`;
- Transport: `HTTPS`;
- Execution mode: `STANDARD_USER`;
- Integrity: `MEDIUM`;
- Elevated: `NO`;
- Receipt: `VERIFIED`;
- coverage ja findings on nähtavad.

Genereeri üks unified report, ava see ilma CSA serverita ning kontrolli
Executive Summary, Endpoint Details, Coverage Gaps ja Audit and Integrity
peatükke. Lõpuks vajuta **Stop Collection** ja kinnita, et firewall access ei ole
enam aktiivne.

## Acceptance'i tõend

Sprint 5.1 lõplik true non-admin acceptance peab kasutama päris teist Windows
11 arvutit. GitHub hosted smoke ega sama arvuti synthetic test ei asenda seda.
