#!/usr/bin/env python3
"""
evil_twin_detector.py — Rilevatore difensivo di rogue AP / evil twin / beacon flood.

Strumento PASSIVO. Ascolta beacon e probe-response e segnala:
  * EVIL TWIN  : stesso SSID annunciato da BSSID diversi, o con sicurezza diversa
                 (es. la tua rete WPA2 che appare anche come "aperta").
  * NEW AP     : nuovo BSSID per un SSID gia' noto.
  * BEACON FLOOD: comparsa rapida di moltissimi BSSID nuovi (attacco tipo mdk4).

Nota: avere piu' AP con lo stesso SSID e' normale in reti mesh/multi-AP. Lo
strumento li segnala come "da verificare", non come certezza di attacco.

Uso:
    sudo python3 evil_twin_detector.py -i wlan0mon
    sudo python3 evil_twin_detector.py -i wlan0mon --log eventi.csv
    sudo python3 evil_twin_detector.py -i wlan0mon -k "I1-UFFICIO" "CasaMia"  # SSID da sorvegliare
"""
import argparse
import csv
import os
import sys
import time
from collections import defaultdict, deque

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
except ImportError:
    sys.exit("Scapy non trovato. Installa con:  pip install scapy")


def get_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            try:
                return elt.info.decode(errors="replace") or "<hidden>"
            except Exception:
                return "<?>"
        elt = elt.payload.getlayer(Dot11Elt)
    return "<hidden>"


def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        if elt.ID == 3 and elt.info:
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def get_security(pkt):
    """Ritorna una stringa tipo OPEN / WPA / WPA2 / WPA3."""
    has_rsn = has_wpa = sae = False
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None and isinstance(elt, Dot11Elt):
        if elt.ID == 48:  # RSN -> WPA2/WPA3
            has_rsn = True
            # AKM SAE (00-0f-ac:8/9) => WPA3
            if b"\x00\x0f\xac\x08" in bytes(elt.info) or b"\x00\x0f\xac\x09" in bytes(elt.info):
                sae = True
        elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":  # WPA vendor IE
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    privacy = "privacy" in cap
    if sae:
        return "WPA3"
    if has_rsn:
        return "WPA2"
    if has_wpa:
        return "WPA"
    return "WPA?" if privacy else "OPEN"


class RogueDetector:
    def __init__(self, watch, flood_threshold, logfile):
        self.watch = {s.lower() for s in watch} if watch else None
        self.ssid_bssids = defaultdict(set)        # ssid -> {bssid}
        self.ssid_security = defaultdict(set)       # ssid -> {security}
        self.known_bssids = {}                      # bssid -> (ssid, chan, sec)
        self.new_bssid_times = deque()              # per il beacon flood
        self.flood_threshold = flood_threshold
        self.alerts = 0
        self.writer = None
        if logfile:
            self._fh = open(logfile, "a", newline="")
            self.writer = csv.writer(self._fh)
            if self._fh.tell() == 0:
                self.writer.writerow(["timestamp", "evento", "ssid", "bssid", "canale", "sicurezza", "dettaglio"])

    def _log(self, evento, ssid, bssid, chan, sec, detail=""):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        color = "\033[91m" if evento.startswith(("EVIL", "BEACON")) else "\033[93m"
        print(f"{color}[{ts}] {evento:12} ssid='{ssid}' bssid={bssid} "
              f"ch={chan} sec={sec} {detail}\033[0m")
        if self.writer:
            self.writer.writerow([ts, evento, ssid, bssid, chan, sec, detail])
            self._fh.flush()

    def handle(self, pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return
        bssid = pkt.addr3
        if not bssid:
            return
        ssid = get_ssid(pkt)
        if self.watch is not None and ssid.lower() not in self.watch:
            return
        chan = get_channel(pkt)
        sec = get_security(pkt)

        # --- Beacon flood: conteggio nuovi BSSID nell'ultimo secondo ---
        if bssid not in self.known_bssids:
            now = time.time()
            self.new_bssid_times.append(now)
            while self.new_bssid_times and now - self.new_bssid_times[0] > 1.0:
                self.new_bssid_times.popleft()
            if len(self.new_bssid_times) >= self.flood_threshold:
                self.alerts += 1
                self._log("BEACON_FLOOD", ssid, bssid, chan, sec,
                          f"{len(self.new_bssid_times)} nuovi BSSID/s")

        # --- Evil twin: stesso SSID con BSSID o sicurezza diversi ---
        first_time_ssid = ssid not in self.ssid_bssids
        new_for_ssid = bssid not in self.ssid_bssids[ssid]
        self.ssid_bssids[ssid].add(bssid)
        self.ssid_security[ssid].add(sec)

        if new_for_ssid and not first_time_ssid and ssid not in ("<hidden>", "<?>"):
            self.alerts += 1
            self._log("EVIL_TWIN?", ssid, bssid, chan, sec,
                      f"SSID gia' visto su {len(self.ssid_bssids[ssid])} BSSID -> verifica")
        if len(self.ssid_security[ssid]) > 1 and ssid not in ("<hidden>", "<?>"):
            self._log("SEC_MISMATCH", ssid, bssid, chan, sec,
                      f"sicurezza vista: {sorted(self.ssid_security[ssid])}")

        if bssid not in self.known_bssids:
            self.known_bssids[bssid] = (ssid, chan, sec)
            if first_time_ssid:
                self._log("NEW_AP", ssid, bssid, chan, sec)

    def close(self):
        if self.writer:
            self._fh.close()


def main():
    ap = argparse.ArgumentParser(description="Rilevatore rogue AP / evil twin / beacon flood")
    ap.add_argument("-i", "--iface", required=True, help="interfaccia in monitor mode")
    ap.add_argument("-k", "--watch", nargs="+", help="SSID da sorvegliare (default: tutti)")
    ap.add_argument("--flood-threshold", type=int, default=20,
                    help="nuovi BSSID/s oltre cui segnalare beacon flood (default: 20)")
    ap.add_argument("--log", help="file CSV su cui registrare gli eventi")
    ap.add_argument("--hop", action="store_true",
                    help="channel hopping 1->11 (2.4GHz) per scansione piu' ampia")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Servono privilegi di root. Rilancia con sudo.")

    det = RogueDetector(args.watch, args.flood_threshold, args.log)
    print(f"[*] Sorveglianza su {args.iface}"
          + (f" | SSID: {args.watch}" if args.watch else " | tutti gli SSID"))
    if args.hop:
        # Hopping semplice in un thread separato.
        import threading
        def hopper():
            ch = 1
            while True:
                os.system(f"iw dev {args.iface} set channel {ch} 2>/dev/null")
                ch = ch % 11 + 1
                time.sleep(0.5)
        threading.Thread(target=hopper, daemon=True).start()
        print("[*] Channel hopping attivo (1-11).")
    print("[*] Ctrl+C per terminare.\n")
    try:
        sniff(iface=args.iface, prn=det.handle, store=False)
    except OSError as e:
        sys.exit(f"Errore sull'interfaccia '{args.iface}': {e} (monitor mode attiva?)")
    except KeyboardInterrupt:
        pass
    finally:
        det.close()
        print(f"\n[+] Terminato. AP unici visti: {len(det.known_bssids)} | allarmi: {det.alerts}")


if __name__ == "__main__":
    main()
