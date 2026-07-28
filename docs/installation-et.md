# CSA Lab paigaldamine

## Nõuded

- Windows 11 x64 laboriarvuti;
- kasutajakonto, mis saab vajadusel kinnitada ühe Windows Firewalli UAC dialoogi;
- labori- ja testarvuti samas usaldatud LAN-is;
- release-artifact `CSA-Lab-Setup.exe`.

Pythonit, Git-i, Node.js-i, Dockerit ega veebiserverit ei ole lõppkasutajal
vaja paigaldada.

## Paigaldamine

1. Laadi GitHub Actionsi või release'i juurest `CSA-Lab-Setup.exe`.
2. Kontrolli release'is avaldatud SHA-256 räsi:

   ```powershell
   Get-FileHash .\CSA-Lab-Setup.exe -Algorithm SHA256
   ```

3. Käivita installer.
4. Jäta vaikimisi per-user paigalduskataloog.
5. Ava Start-menüüst **CSA Lab**.

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
