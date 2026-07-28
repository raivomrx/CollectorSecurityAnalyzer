# CSA unified HTML raport

CSA Lab loob ühe põhiraporti:

```text
<Assessment-Name>-CSA-Assessment-Report.html
```

Raport sisaldab Executive Summary, scope'i, riski ja coverage'i, fleet
dashboard'i, priority/systemic findings'eid, remediation plan'i, endpointide
võrdlust ja detaili, coverage gap'e, framework mapping'ut, technical evidence'it,
metoodikat ning audit-integrity osa.

## Omadused

- üks HTML fail;
- CSS ja JavaScript on failisisesed;
- puuduvad CDN-id ja serverisõltuvus;
- töötab offline'is ja teises arvutis;
- klikitav sisukord;
- lokaalne otsing ja filtrid;
- endpointid ja evidence on vaikimisi kokkupandavad;
- print CSS avab detailid printimise ajaks;
- deterministic fleet grouping ja latest-submission valik;
- raw saladusi, võtmeid, recovery key'sid ega credential material'i ei kuvata.

## Genereerimine

1. Oota vähemalt ühe endpointi staatust `COMPLETE`.
2. Kontrolli preview's included endpointide, rejected submission'ite ja coverage
   gap'ide arvu.
3. Jäta vaikimisi sisse endpoint details, technical evidence ja audit.
4. Vajuta **Generate Assessment Report**.
5. Kasuta **Open Report** või **Show in Folder**.

Legacy endpoint/fleet/executive raportid jäävad Advanced/CLI kasutuseks.
Kliendile piisab unified raportist.

## Tõlgendamine

Coverage ja security score ei ole sama näitaja. Puuduv evidence tekitab coverage
gap'i, mitte automaatselt turvavea. Framework mapping annab traceability, kuid ei
tõenda iseseisvalt sertifitseerimist või täielikku vastavust.
