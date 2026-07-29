# CSA Lab paigaldamine

## Nõuded

- Windows 11 x64 laboriarvuti;
- kasutajakonto, mis saab vajadusel kinnitada ühe Windows Firewalli UAC dialoogi;
- labori- ja testarvuti samas usaldatud LAN-is;
- GitHubi konto, millega on võimalik repository Actions artifact alla laadida.

Pythonit, Git-i, Node.js-i, Dockerit ega veebiserverit ei ole lõppkasutajal
vaja paigaldada.

## Paigaldamine

1. Ava GitHubis **Actions** → **CSA Lab Build**.
2. Ava uusim edukas `main` haru workflow run.
3. Leia run'i **Summary** lehe allosast **Artifacts**.
4. Laadi alla artifact nimega **CSA-Lab-Setup**.
5. Paki allalaaditud ZIP lahti. See sisaldab faile:

   ```text
   CSA-Lab-Setup.exe
   SHA256SUMS.txt
   ```

   GitHub Actions artifacti allalaadimiseks peab olema GitHubi sisse logitud.
   Artifact ei asu repository lähtekoodifailide ega Releases loendi all.

6. Kontrolli installerit `SHA256SUMS.txt` faili alusel:

   ```powershell
   (Get-FileHash .\CSA-Lab-Setup.exe -Algorithm SHA256).Hash
   Get-Content .\SHA256SUMS.txt
   ```

7. Käivita installer.
8. Jäta vaikimisi per-user paigalduskataloog.
9. Ava Start-menüüst **CSA Lab**.

Artifact **CSA-Lab-Windows** on arendajatele mõeldud täielik build-pakett, mis
sisaldab lisaks installerile lahtipakitud CSA Lab rakendust ja Collector
bootstrapperit. Tavaliseks paigalduseks kasuta **CSA-Lab-Setup** artifacti.

GitHub Release'i ei ole Sprint 5.1 praegusest unsigned buildist veel tehtud.
Püsiv release avaldatakse pärast true non-admin acceptance-testi ja production
Authenticode allkirjastamist.

Rakendus paigaldatakse kasutaja `AppData\Local\Programs\CSA Lab` alla.
Püsivad assessment'id, logid, võtmed ja raportid asuvad
`%LOCALAPPDATA%\CSA` all. Andmed ei asu installatsioonikataloogis.

## Windowsi hoiatused

Kui production code-signing sertifikaati ei ole veel kasutatud, võib
SmartScreen kuvada tundmatu avaldaja hoiatuse. Kontrolli enne jätkamist
release'i allikat ja SHA-256 räsi. Production-release peab allkirjastama
`CSA-Lab-Setup.exe`, `CSA-Lab.exe` ja `CSA-Collector.exe`.

## Uuendamine ja eemaldamine

Uue versiooni installer võib asendada rakenduse failid. Assessment'i andmed
jäävad eraldi andmekataloogi. Uninstaller jätab `%LOCALAPPDATA%\CSA` sisu alles,
et evidence ja audit ei kaoks vaikimisi. Andmete kustutamine peab olema
eraldi teadlik toiming pärast vajalikku eksporti ja varundust.

CSA Lab ei paigalda Windowsi teenust ega käivita collection-serverit Windowsi
startup'is.
