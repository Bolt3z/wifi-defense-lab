# Lab di sicurezza WiFi — Deauth attack & detection

Laboratorio **didattico** per capire e difendersi dagli attacchi di
*deauthentication* 802.11 ("WiFi jamming" di livello 2).

> ⚠️ **USO AUTORIZZATO SOLTANTO**
> Usa questi strumenti **esclusivamente** su reti e dispositivi che possiedi,
> o per cui hai autorizzazione scritta. Inviare frame deauth verso reti altrui
> è un attacco DoS ed è **illegale** (in CH: violazione LTC/ordinanze UFCOM,
> art. del Codice penale su danneggiamento/perturbamento). Lo scopo qui è
> imparare a **rilevare e mitigare** questi attacchi sulla tua rete.

## Cosa NON c'è qui (e perché)

Niente "jammer RF": trasmettere rumore sullo spettro 2.4/5 GHz è illegale e
fisicamente impossibile con una chiavetta WiFi. Ciò che comunemente si chiama
"jammer WiFi" è in realtà l'attacco **deauth** qui sotto: non disturba la radio,
ma sfrutta il fatto che i frame di *gestione* 802.11 (deauth/disassoc) **non
sono autenticati** in WPA2. La difesa è il **Management Frame Protection (802.11w / PMF)**, attivo di default in **WPA3**.

## Requisiti hardware

Adattatore WiFi USB con **monitor mode + packet injection**. Chipset consigliati:

| Chipset            | Driver Linux  | Note                          |
|--------------------|---------------|-------------------------------|
| Atheros AR9271     | `ath9k_htc`   | Il più affidabile, plug&play  |
| MediaTek MT7612U   | `mt76x2u`     | Dual-band 2.4/5 GHz           |
| Realtek RTL8812AU  | `88XXau` (dkms)| Dual-band, driver da installare |

La scheda **interna Intel** in genere NON va bene per l'injection.

## Verifica hardware

```bash
lsusb                       # individua il chipset della chiavetta
iw dev                      # nome interfaccia (es. wlan0)
iw list | grep -A8 "Supported interface modes"   # deve elencare "monitor"
```

Test injection (dopo il setup monitor mode):

```bash
sudo aireplay-ng --test wlan0mon
```

## Workflow del lab

1. **Setup**: `sudo ./setup_monitor.sh wlan0` → crea un'interfaccia monitor.
2. **Ricognizione**: `sudo airodump-ng wlan0mon` → trova BSSID/canale del *tuo* AP
   e il MAC del *tuo* dispositivo di test.
3. **Difesa (consigliato iniziare da qui)**: in un terminale lancia il detector
   `sudo python3 deauth_detector.py -i wlan0mon -c <canale>`.
4. **Attacco controllato**: in un altro terminale
   `sudo python3 deauth_test.py -i wlan0mon -b <BSSID_TUO_AP> -c <MAC_TUO_CLIENT> --channel <canale>`.
5. **Osserva**: il detector segnala l'attacco; il tuo dispositivo si disconnette.
6. **Mitiga**: attiva WPA3/PMF sul router e ripeti — l'attacco non funziona più.

## Mitigazioni (l'obiettivo finale)

- **WPA3** o almeno **WPA2 con PMF (802.11w) impostato su "Required"**.
- Verifica che i tuoi client supportino PMF (la maggior parte dei dispositivi recenti sì).
- Monitoraggio continuo dei frame deauth anomali (vedi `deauth_detector.py`).

## File

- `setup_monitor.sh`      — attiva/disattiva monitor mode
- `deauth_detector.py`    — sniffer difensivo: rileva attacchi deauth/disassoc
- `deauth_test.py`        — attacco deauth controllato sul TUO AP (con guardrail)
- `evil_twin_detector.py` — rileva rogue AP / evil twin / beacon flood (+log CSV)
- `pmf_audit.py`          — verifica se i tuoi AP hanno PMF/802.11w attivo
- `capture_handshake.sh`  — cattura handshake WPA2 e ne testa la robustezza
- `HARDENING.md`          — checklist di hardening con verifica prima/dopo
- `requirements.txt`      — dipendenze Python

## Percorso di apprendimento consigliato

1. **Capire l'attacco** → `deauth_test.py` + `deauth_detector.py` (vedi un client cadere).
2. **Rilevare** → `evil_twin_detector.py` (riconoscere attacchi nell'aria).
3. **Misurare la robustezza** → `capture_handshake.sh` (quanto è forte la tua password?).
4. **Mitigare e verificare** → `HARDENING.md` + `pmf_audit.py` (attiva WPA3/PMF e ricontrolla).
