# CSA offline-hindamine

Offline-voog on varuvariant juhuks, kui testarvuti ei saa CSA Labi HTTPS
listeneriga ühendust.

## Endpoint

1. Käivita assessment-bound `CSA-Collector.exe` tavakasutajana.
2. Kui online-submit ebaõnnestub, vali **create Offline package**.
3. Collector kogub evidence'i uuesti ja loob töölauale `.csa` faili.
4. Teisalda fail kontrollitud andmekandja või muu volitatud kanali kaudu
   laboriarvutisse.

Offline package on assessment- ja session-bound. See kasutab hübriidset
krüpteerimist, autentimist, expiry't, package digest'i ning submission ID-d.
Plaintext enrollment credential ei jää eraldi faili.

## CSA Lab

1. Ava õige assessment.
2. Vajuta **Import Offline Package**.
3. Vali `.csa` fail.
4. CSA kontrollib assessment'i, krüptograafilist terviklust, build trust'i,
   duplicate/replay olekut, skeemi ja privacy policy't.
5. Edu korral kuvatakse endpoint samas tabelis transpordiga `OFFLINE`.

Tampered, teise assessment'i või dubleeritud fail lükatakse tagasi. Rejected või
quarantined evidence ei lähe analüüsi ega unified raportisse.
