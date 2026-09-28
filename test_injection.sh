#!/usr/bin/env bash
#
# test_injection.sh — diagnostica monitor mode + packet injection (senza airodump).
#
# Strategia anti-blocco: usa solo `aireplay-ng --test`, che TERMINA da solo.
# Lo prova su piu' canali con AP probabili (1/6/11 in 2.4GHz, 36-48 in 5GHz
# non-DFS). Appena un AP risponde su un canale, l'injection e' confermata.
#
# Uso:
#   sudo ./test_injection.sh                          # auto: prova vari canali
#   sudo ./test_injection.sh -b AA:BB:CC:DD:EE:FF -c 36   # test DIRETTO sul TUO AP
#   sudo ./test_injection.sh -k                       # resta in monitor a fine test
#
set -uo pipefail

IFACE="wlx000f00a7d33e"
BSSID=""
CH=""
KEEP="no"

while getopts "i:b:c:k" opt; do
  case $opt in
    i) IFACE=$OPTARG ;;
    b) BSSID=$OPTARG ;;
    c) CH=$OPTARG ;;
    k) KEEP="yes" ;;
    *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
  esac
done

[[ "$EUID" -ne 0 ]] && { echo "Servono privilegi di root (sudo)." >&2; exit 1; }

restore_wifi() {
  echo
  echo "=== Ripristino WiFi (managed + NetworkManager) ==="
  ip link set "$IFACE" down 2>/dev/null || true
  iw dev "$IFACE" set type managed 2>/dev/null || true
  ip link set "$IFACE" up 2>/dev/null || true
  systemctl restart NetworkManager 2>/dev/null || systemctl start NetworkManager 2>/dev/null || true
  echo "  [+] WiFi riattivato."
}

# Esegue un singolo test di injection sul canale corrente. Stampa l'output.
# Ritorna: 0 = injection confermata, 1 = nessuna risposta, 2 = errore di TX.
run_test() {
  local out
  if [[ -n "$BSSID" ]]; then
    out=$(timeout --kill-after=3 20 aireplay-ng --test -a "$BSSID" "$IFACE" 2>&1)
  else
    out=$(timeout --kill-after=3 20 aireplay-ng --test "$IFACE" 2>&1)
  fi
  echo "$out" | sed 's/^/      /'
  if echo "$out" | grep -qiE "Injection is working|Ping .*min/avg/max|[1-9][0-9]*/[0-9]+:|[1-9][0-9]* out of"; then
    return 0
  elif echo "$out" | grep -qiE "Operation not permitted|wi_write|fail|denied|not support"; then
    return 2
  fi
  return 1
}

echo "=== 1. Chipset/driver ==="
DRV=$(basename "$(readlink -f /sys/class/net/$IFACE/device/driver 2>/dev/null)" 2>/dev/null || echo "?")
echo "    interfaccia: $IFACE   driver: $DRV"
case "$DRV" in
  rtl88x2bu|88x2bu|8812au|8821au|8814au) echo "    -> driver out-of-tree: injection attesa OK" ;;
  rtw88*|iwlwifi) echo "    -> driver mainline: injection spesso NON supportata" ;;
esac

echo "=== 2. Attivo monitor mode ==="
airmon-ng check kill >/dev/null 2>&1 || true
ip link set "$IFACE" down
iw dev "$IFACE" set monitor control 2>/dev/null || iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
iw dev "$IFACE" info | grep -E "type" | sed 's/^/    /'

echo "=== 3. Test injection ==="
RESULT=1
TXERR=0
if [[ -n "$CH" ]]; then
  CHANNELS="$CH"
else
  CHANNELS="1 6 11 36 40 44 48"
  echo "    (provo piu' canali finche' un AP risponde; ognuno dura pochi secondi)"
fi
for c in $CHANNELS; do
  iw dev "$IFACE" set channel "$c" 2>/dev/null || { echo "    canale $c: non impostabile, salto"; continue; }
  echo "    --- canale $c ---"
  run_test; rc=$?
  if [[ $rc -eq 0 ]]; then RESULT=0; FOUNDCH=$c; break; fi
  [[ $rc -eq 2 ]] && TXERR=1
done

echo
echo "=== VERDETTO ==="
if [[ $RESULT -eq 0 ]]; then
  echo "  ✅ INJECTION FUNZIONA (confermata sul canale ${FOUNDCH})."
  echo "     Sei pronto per tutto il lab. Prossimo passo:"
  echo "       sudo ./setup_monitor.sh $IFACE        # monitor mode stabile"
  echo "       sudo airodump-ng $IFACE               # trova BSSID/canale del TUO AP"
  echo "     poi deauth_detector.py + deauth_test.py, infine HARDENING.md + pmf_audit.py."
elif [[ $TXERR -eq 1 ]]; then
  echo "  ❌ Errore di TRASMISSIONE col driver '$DRV': injection non disponibile."
  echo "     Reinstalla il driver morrownr e RIAVVIA:"
  echo "       cd ~/Projects/88x2bu-20210702 && sudo ./install-driver.sh"
else
  echo "  ⚠ INCONCLUSIVO: nessun AP ha risposto sui canali provati."
  echo "     Non significa per forza injection rotta: forse non c'erano AP sui"
  echo "     canali testati. Fai un test DIRETTO verso una rete che vedi (la tua):"
  echo "       # 1) trova un AP e il suo canale:"
  echo "       sudo ./setup_monitor.sh $IFACE && sudo airodump-ng $IFACE   # Ctrl+C dopo averne visto uno"
  echo "       # 2) test diretto su quell'AP:"
  echo "       sudo $0 -b <BSSID> -c <canale>"
fi

[[ "$KEEP" == "yes" ]] || restore_wifi
