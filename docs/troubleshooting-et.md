# CSA Lab tõrkeotsing

## Collector page ei avane

Kontrolli:

- CSA Labis on staatus `COLLECTING`;
- kuvatud IP kuulub valitud laboriarvuti adapterile;
- mõlemad arvutid on samas subnetis;
- laboriarvuti network profile on Private või Domain;
- ajutine `CSA Lab Temporary ...` firewall rule on aktiivne;
- URL ja join code on kopeeritud täielikult;
- session ei ole aegunud.

Veakood: `CSA-NET-001`.

## Firewall UAC lükati tagasi

Collection ei käivitu. Evidence'i ega assessment'i ei kustutata. Vajuta Start
uuesti ning kinnita laboriarvutis üks UAC dialoog. Testarvuti ei tohi UAC-d
saada.

Veakoodid: `CSA-NET-002`, `CSA-NET-003`, `CSA-NET-004`.

## Brauser kuvab certificate warning'u

Generated assessment certificate ei kuulu brauseri tavalisse trust store'i.
Võrdle URL-i IP-d CSA Labis kuvatuga. Collectori HTTPS-submit kontrollib täpset
certificate fingerprint'i ja ei kasuta browseri bypass'i.

## Collector ütleb elevated või integrity error

Sulge Collector. Käivita fail tavalise topeltklõpsuga. Ära kasuta **Run as
administrator**. Standard-user flow nõuab medium-integrity protsessi ja katkeb
elevated/SYSTEM kontekstis fail-closed.

## Submission ei jõua kohale

Kontrolli collection'i olekut, session expiry't ja võrku. Proovi Collectoris
Retry. Kui ühendus ei ole võimalik, loo encrypted offline package.

## Endpoint on ERROR

Vali endpoint ja vaata processing state'i. Hoia evidence alles. Logid asuvad
`%LOCALAPPDATA%\CSA\logs`. Logi ei tohiks sisaldada tokeneid ega evidence'i
saladusi.

## Recovery required

See tähendab, et eelmine CSA Lab või Windows sulgus aktiivse collection'i ajal
või ajutine firewall rule jäi alles. Vali:

- **Resume Assessment**, et kontrollid uuesti avada;
- **Close and Clean Up**, et session sulgeda ja firewall eemaldada.

Recovery ei kustuta vastuvõetud evidence'i.

## Audit FAILED

Ära väljasta raportit lõpptulemusena. Säilita assessment'i kataloog, sulge
collection ja tee forensic/diagnostic review. Audit failure kuvatakse kriitilise
terviklusprobleemina.

## Support vajab diagnostikat

Ava **Settings → Advanced → Export Diagnostic Bundle**. CSA loob ZIP-faili,
mis sisaldab puhastatud roteeruvaid logisid ja agregeeritud auditistaatust.
Paketti ei lisata evidence-faile, võtmeid, tokeneid ega täisidentiteete.
