# CSA TLS ja sertifikaadid

## Kaks erinevat kasutusjuhtu

CSA Lab kasutab sama scoped HTTPS listenerit Collectori allalaadimiseks ja
evidence'i vastuvõtmiseks, kuid browseri ja Collectori trust-mudel on erinev.

Brauser ei usalda vaikimisi lühiajalist generated self-signed sertifikaati ja
võib kuvada hoiatuse. Enne jätkamist peab kasutaja võrdlema URL-i laboriarvuti
CSA Labis kuvatud IP-ga.

Collector ei tugine browseri otsusele. Assessment-bound konfiguratsioon sisaldab
täpset server certificate fingerprint'i. PowerShelli HTTPS klient:

- nõuab TLS-i;
- kontrollib sertifikaadi fingerprint'i constant-time võrdlusega;
- ei kasuta `verify=False`, `SkipCertificateCheck` ega HTTP fallback'i;
- seob nonce'i ja submission'i sama session'iga.

Brauseri warning'ust möödumine ei lülita Collectori pinning'ut välja.

## Trusted certificate

Arhitektuur lubab tulevikus valida organisatsiooni CA või Windows certificate
store'i sertifikaadi. Sprint 5.1 generated certificate on turvaline fallback.
CSA ei paigalda testarvutisse automaatselt root CA sertifikaati.

CSA Home peab tulevikus kasutama lokaalset `file://`, localhost või native report
viewer lahendust ning ei tohi tavakasutuses tekitada remote self-signed TLS
hoiatust.
