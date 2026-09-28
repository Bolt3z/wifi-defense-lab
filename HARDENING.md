# Hardening WiFi — checklist guidata

Obiettivo: rendere le tue reti resistenti agli attacchi che hai testato nel lab
(deauth/jamming L2, evil twin, crack offline dell'handshake). Per ogni misura:
*cosa fare → perché → come verificarlo con gli strumenti del lab*.

---

## 1. Attiva WPA3 (o almeno WPA2 + PMF "Required")

**Perché.** I deauth funzionano perché in WPA2 i frame di gestione non sono
autenticati. Il **Management Frame Protection (802.11w / PMF)** li firma: i
deauth falsificati vengono ignorati. WPA3-SAE include PMF *obbligatorio* e
rende inefficace anche il crack offline dell'handshake.

**Come fare (interfaccia del router — i nomi variano):**
- Sicurezza wireless → **WPA3-Personal**, oppure **WPA2/WPA3 transition**.
- Se resti su WPA2: cerca **Protected Management Frames / 802.11w → Required**.
  Evita "Optional" se tutti i tuoi dispositivi supportano PMF.

**Verifica nel lab:**
```bash
sudo python3 pmf_audit.py -i wlan0mon -k "TuoSSID"
# Esito atteso: "PMF REQUIRED" o WPA3-SAE
sudo python3 deauth_test.py -i wlan0mon -b <BSSID> -c <CLIENT> --channel <ch> --count 32
# Atteso dopo l'hardening: il client NON si disconnette piu'
```

> ⚠️ "Transition mode" (WPA2+WPA3) lascia PMF opzionale per i client WPA2: un
> attaccante puo' forzare il downgrade. Se i dispositivi lo reggono, vai full WPA3.

---

## 2. Passphrase forte (difesa contro il crack dell'handshake)

**Perché.** Con WPA2-PSK chiunque cattura l'handshake e prova offline milioni di
password. Una passphrase **lunga e casuale** (≥ 15 caratteri, non in dizionario)
rende il crack impraticabile.

**Verifica nel lab:**
```bash
sudo ./capture_handshake.sh -i wlan0mon -b <BSSID> -h <ch> -c <CLIENT> -w wordlist.txt
# Atteso: password NON trovata. Se viene trovata, cambiala subito.
```

---

## 3. Rileva evil twin / rogue AP

**Perché.** Un attaccante puo' clonare il tuo SSID per intercettare i client.

**Verifica/monitoraggio continuo:**
```bash
sudo python3 evil_twin_detector.py -i wlan0mon -k "TuoSSID" --log eventi.csv --hop
```
Indaga ogni `EVIL_TWIN?` o `SEC_MISMATCH` che non corrisponda ai tuoi AP legittimi.

---

## 4. Igiene di rete (riduci la superficie d'attacco)

- **WPS: disattivato.** Vulnerabile ad attacchi PIN (es. Pixie Dust).
- **Firmware del router aggiornato** (chiude bug noti).
- **Password admin del router** cambiata da quella di default.
- **SSID** non rivelatore di marca/modello (aiuta chi cerca exploit noti).
- **Rete ospiti isolata** per IoT/visite, separata dalla LAN principale.
- **Banda 5/6 GHz** quando possibile: portata minore = minore esposizione esterna.
- **Riduci la potenza TX** se copri più del necessario fuori casa.

---

## 5. Limiti che restano (onestà tecnica)

- Il **jamming RF puro** (rumore radio) NON è mitigabile lato protocollo: è un
  problema fisico dello spettro. Difesa = rilevarlo (calo SNR/floor di rumore)
  ed eventualmente passare a cavo/altra banda. Non lo trattiamo nel lab perché
  costruire un jammer RF è illegale.
- PMF protegge i frame di **gestione**, non elimina ogni DoS L1/L2 esotico, ma
  chiude la stragrande maggioranza degli attacchi "jammer" reali (i deauth).

---

## Riepilogo verifica "prima/dopo"

| Test                         | Prima (WPA2 base) | Dopo (WPA3/PMF + pwd forte) |
|------------------------------|-------------------|-----------------------------|
| `deauth_test.py`             | client si disconnette | client resta connesso ✔ |
| `pmf_audit.py`               | PMF assente       | PMF required / WPA3 ✔        |
| `capture_handshake.sh` + crack | rischio se pwd debole | crack fallisce ✔        |
