# CSA Lab kiirjuhend

1. Ava laboriarvutis **CSA Lab**.
2. Vajuta **New Assessment**.
3. Sisesta nimi ja testarvutite arv.
4. Kinnita õige Private või Domain võrguliides.
5. Vajuta **Create Assessment** ja seejärel **Start Collection**.
6. Kinnita laboriarvutis Windows Firewalli UAC dialoog.
7. Vajuta aktiivses assessment'is **Copy Collector Page**.
8. Sulge testarvutis varasem CSA sakk ja kleebi kogu uus aadress brauseri
   aadressiribale. Igal assessment'il on erinev ja aeguv join URL.
9. Veendu, et aadressi IP kuulub laboriarvutile. Ajutise sertifikaadi tõttu võib
   brauser kuvada hoiatuse.
10. Laadi alla ja käivita `CSA-Collector.exe` tavakasutajana. Ära kasuta
    **Run as administrator**.
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
impordi `.csa` fail CSA Labi nupuga **Import Offline Package**.
