# CSA Lab kiirjuhend

1. Ava laboriarvutis **CSA Lab**.
2. Vajuta **New Assessment**.
3. Sisesta nimi ja testarvutite arv.
4. Kinnita õige Private või Domain võrguliides.
5. Vajuta **Create Assessment** ja seejärel **Start Collection**.
6. Kinnita laboriarvutis Windows Firewalli UAC dialoog.
7. Ava testarvuti brauseris CSA Labis näidatud **Collector page** aadress.
8. Veendu, et aadressi IP kuulub laboriarvutile. Ajutise sertifikaadi tõttu võib
   brauser kuvada hoiatuse.
9. Laadi alla ja käivita `CSA-Collector.exe` tavakasutajana. Ära kasuta
   **Run as administrator**.
10. Oota teadet **Submission accepted**.
11. Kontrolli CSA Labis, et endpoint on **Complete**, transport on **HTTPS**,
    execution mode on standard user ja integrity on medium.
12. Vajuta **Generate Assessment Report**, seejärel **Open Report**.
13. Vajuta pärast viimast endpointi **Stop Collection**.
14. Vajadusel vali **Export Assessment Archive** ja kasuta vähemalt
    12-märgilist tugevat parooli.

Kui võrguühendus ei tööta, vali Collectoris encrypted offline package ning
impordi `.csa` fail CSA Labi nupuga **Import Offline Package**.
