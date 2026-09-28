#!/usr/bin/env python3
"""
deauth_detector.py — Rilevatore difensivo di attacchi deauthentication 802.11.

Ascolta in monitor mode i frame di gestione deauth (subtype 12) e disassoc
(subtype 10). Questi frame in WPA/WPA2 NON sono autenticati: chiunque puo'
falsificarli. Un'ondata (burst) di deauth verso un client o in broadcast e' il
segnale tipico di un attacco "WiFi jammer" di livello 2.

Questo strumento e' puramente PASSIVO e DIFENSIVO: si limita ad ascoltare.

Uso:
    sudo python3 deauth_detector.py -i wlan0mon
    sudo python3 deauth_detector.py -i wlan0mon -c 6        # blocca sul canale 6
    sudo python3 deauth_detector.py -i wlan0mon -t 10       # soglia allarme = 10/s

Richiede: interfaccia gia' in monitor mode (vedi setup_monitor.sh) e Scapy.
"""
import argparse
import os
import sys
import time
from collections import defaultdict, deque

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas
except ImportError:
    sys.exit("Scapy non trovato. Installa con:  pip install scapy")

# Codici motivo (reason code) tipici usati negli attacchi deauth.
REASON_CODES = {
    1: "Unspecified",
    2: "Previous auth no longer valid",
    3: "Deauth: leaving",
    4: "Inactivity",
    6: "Class 2 frame from nonauth STA",
    7: "Class 3 frame from nonassoc STA",   # il piu' usato negli attacchi
    8: "Disassoc: leaving",
}


class DeauthMonitor:
    def __init__(self, threshold, window=1.0):
        # Finestra scorrevole di timestamp per (sorgente -> destinazione).
        self.events = defaultdict(deque)
        self.threshold = threshold          # frame/sec oltre cui scatta l'allarme
        self.window = window                # ampiezza finestra in secondi
        self.total = 0
        self.alerts = 0
        self.in_alert = set()               # coppie gia' in stato di allarme

    def handle(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        is_deauth = pkt.haslayer(Dot11Deauth)
        is_disas = pkt.haslayer(Dot11Disas)
        if not (is_deauth or is_disas):
            return

        self.total += 1
        src = pkt.addr2 or "??"             # trasmettitore (spesso il BSSID falsificato)
        dst = pkt.addr1 or "??"             # vittima (o ff:ff:ff:ff:ff:ff = broadcast)
        bssid = pkt.addr3 or "??"
        kind = "DEAUTH " if is_deauth else "DISASSOC"
        reason = pkt[Dot11Deauth].reason if is_deauth else pkt[Dot11Disas].reason
        rname = REASON_CODES.get(reason, f"reason {reason}")

        now = time.time()
        key = (src, dst)
        q = self.events[key]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        rate = len(q)

        ts = time.strftime("%H:%M:%S")
        bcast = " [BROADCAST]" if dst.lower() == "ff:ff:ff:ff:ff:ff" else ""

        if rate >= self.threshold:
            if key not in self.in_alert:
                self.in_alert.add(key)
                self.alerts += 1
            print(f"\033[91m[{ts}] ⚠ ATTACCO  {kind} {src} -> {dst}{bcast} "
                  f"| {rate} frame/s | AP={bssid} | {rname}\033[0m")
        else:
            self.in_alert.discard(key)
            print(f"[{ts}] {kind} {src} -> {dst}{bcast} | AP={bssid} | {rname}")


def main():
    ap = argparse.ArgumentParser(description="Rilevatore difensivo di attacchi deauth 802.11")
    ap.add_argument("-i", "--iface", required=True, help="interfaccia in monitor mode (es. wlan0mon)")
    ap.add_argument("-c", "--channel", type=int, help="blocca su un canale specifico")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="frame/s oltre cui segnalare un attacco (default: 5)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Servono privilegi di root. Rilancia con sudo.")

    if args.channel:
        os.system(f"iw dev {args.iface} set channel {args.channel}")
        print(f"[*] Canale impostato a {args.channel}")

    mon = DeauthMonitor(threshold=args.threshold)
    print(f"[*] In ascolto su {args.iface} (soglia allarme: {args.threshold} frame/s).")
    print("[*] Premi Ctrl+C per terminare.\n")
    try:
        sniff(iface=args.iface, prn=mon.handle, store=False)
    except OSError as e:
        sys.exit(f"Errore sull'interfaccia '{args.iface}': {e}\n"
                 "L'interfaccia e' in monitor mode? (vedi setup_monitor.sh)")
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[+] Terminato. Frame deauth/disassoc totali: {mon.total} | "
              f"allarmi attacco: {mon.alerts}")


if __name__ == "__main__":
    main()
