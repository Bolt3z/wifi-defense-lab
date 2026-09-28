#!/usr/bin/env bash
#
# setup_monitor.sh — attiva (o disattiva) la monitor mode preservando il nome
#                    dell'interfaccia (metodo iw, affidabile con i driver rtw88).
#
# USO AUTORIZZATO: solo su hardware tuo, per testare le tue reti.
#
# Esempi:
#   sudo ./setup_monitor.sh wlx000f00a7d33e          # attiva monitor mode
#   sudo ./setup_monitor.sh wlx000f00a7d33e start 6  # attiva + canale 6
#   sudo ./setup_monitor.sh wlx000f00a7d33e stop     # ripristina managed mode
#
set -euo pipefail

IFACE="${1:-}"
ACTION="${2:-start}"
CHANNEL="${3:-}"

if [[ -z "$IFACE" ]]; then
  echo "Uso: sudo $0 <interfaccia> [start|stop] [canale]" >&2
  echo "Interfacce wireless disponibili:" >&2
  iw dev | awk '/Interface/{print "  - "$2}' >&2
  exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "Servono privilegi di root. Rilancia con sudo." >&2
  exit 1
fi

if [[ "$ACTION" == "stop" ]]; then
  echo "[*] Ripristino managed mode su $IFACE ..."
  ip link set "$IFACE" down
  iw dev "$IFACE" set type managed
  ip link set "$IFACE" up
  systemctl restart NetworkManager 2>/dev/null || true
  echo "[+] Fatto. Connettivita' ripristinata."
  exit 0
fi

echo "[*] Chiudo i processi che interferiscono (NetworkManager, wpa_supplicant)..."
airmon-ng check kill >/dev/null 2>&1 || true

echo "[*] Attivo monitor mode su $IFACE (nome preservato) ..."
ip link set "$IFACE" down
# 'monitor control' include i flag utili; fallback a 'type monitor' se non accettato.
iw dev "$IFACE" set monitor control 2>/dev/null || iw dev "$IFACE" set type monitor
ip link set "$IFACE" up

if [[ -n "$CHANNEL" ]]; then
  iw dev "$IFACE" set channel "$CHANNEL"
  echo "[*] Canale impostato a $CHANNEL"
fi

echo
echo "[+] Stato attuale:"
iw dev "$IFACE" info | grep -E "type|channel" | sed 's/^/    /'
echo
echo "    Verifica injection con:  sudo ./test_injection.sh $IFACE"
echo "    Per ripristinare:        sudo $0 $IFACE stop"
