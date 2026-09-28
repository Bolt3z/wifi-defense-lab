#!/usr/bin/env python3
"""
pmf_audit.py — Audit difensivo del Management Frame Protection (802.11w / PMF).

PMF e' la mitigazione DIRETTA contro gli attacchi deauth: protegge i frame di
gestione. Questo strumento ascolta i beacon dei TUOI AP e dice, per ciascuno,
se PMF e':
  * REQUIRED  (MFPR) -> ottimo: i deauth falsificati vengono ignorati
  * CAPABLE   (MFPC) -> opzionale: protetto solo coi client che lo negoziano
  * ASSENTE          -> vulnerabile agli attacchi deauth
e se la rete usa WPA3-SAE (in cui PMF e' obbligatorio).

Usalo per VERIFICARE l'efficacia dell'hardening dopo aver attivato WPA3/PMF
sul router (vedi HARDENING.md).

Uso:
    sudo python3 pmf_audit.py -i wlan0mon
    sudo python3 pmf_audit.py -i wlan0mon -k "CasaMia" --timeout 30
"""
import argparse
import os
import struct
import sys
import time

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
except ImportError:
    sys.exit("Scapy non trovato. Installa con:  pip install scapy")

AKM_NAMES = {1: "802.1X", 2: "PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
             8: "SAE(WPA3)", 9: "FT-SAE", 18: "OWE"}


def parse_rsn(info):
    """Parsa l'Information Element RSN (ID 48). Ritorna dict con akm e flag PMF."""
    out = {"akms": [], "mfpc": False, "mfpr": False}
    try:
        i = 2  # salta version (2 byte)
        i += 4  # group cipher suite
        (pc,) = struct.unpack_from("<H", info, i); i += 2
        i += 4 * pc  # pairwise cipher suites
        (ac,) = struct.unpack_from("<H", info, i); i += 2
        for _ in range(ac):
            oui = info[i:i + 3]; suite = info[i + 3]; i += 4
            if oui == b"\x00\x0f\xac":
                out["akms"].append(AKM_NAMES.get(suite, f"AKM{suite}"))
        if i + 2 <= len(info):
            (caps,) = struct.unpack_from("<H", info, i)
            out["mfpr"] = bool(caps & 0x0040)  # bit 6 = Required
            out["mfpc"] = bool(caps & 0x0080)  # bit 7 = Capable
    except (struct.error, IndexError):
        pass
    return out


def get_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            try:
                return elt.info.decode(errors="replace") or "<hidden>"
            except Exception:
                return "<?>"
        elt = elt.payload.getlayer(Dot11Elt)
    return "<hidden>"


def get_rsn(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            return parse_rsn(bytes(elt.info))
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def verdict(rsn):
    if rsn is None:
        return "\033[91mNO RSN (rete aperta/WPA legacy) — VULNERABILE a deauth\033[0m"
    sae = any("SAE" in a for a in rsn["akms"])
    if rsn["mfpr"]:
        return "\033[92mPMF REQUIRED — protetto dai deauth falsificati ✔\033[0m"
    if rsn["mfpc"]:
        lvl = "\033[92m" if sae else "\033[93m"
        return f"{lvl}PMF CAPABLE (opzionale) — protetto solo coi client che lo negoziano\033[0m"
    return "\033[91mPMF ASSENTE — VULNERABILE agli attacchi deauth\033[0m"


def main():
    ap = argparse.ArgumentParser(description="Audit PMF (802.11w) dei tuoi access point")
    ap.add_argument("-i", "--iface", required=True, help="interfaccia in monitor mode")
    ap.add_argument("-k", "--watch", nargs="+", help="SSID da analizzare (default: tutti)")
    ap.add_argument("--timeout", type=int, default=20, help="durata scansione in secondi (default: 20)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Servono privilegi di root. Rilancia con sudo.")

    watch = {s.lower() for s in args.watch} if args.watch else None
    seen = {}  # bssid -> (ssid, rsn)

    def handle(pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return
        bssid = pkt.addr3
        if not bssid or bssid in seen:
            return
        ssid = get_ssid(pkt)
        if watch is not None and ssid.lower() not in watch:
            return
        seen[bssid] = (ssid, get_rsn(pkt))

    print(f"[*] Scansione PMF per {args.timeout}s su {args.iface}"
          + (f" | SSID: {args.watch}" if args.watch else "") + " ...\n")
    try:
        sniff(iface=args.iface, prn=handle, store=False, timeout=args.timeout)
    except OSError as e:
        sys.exit(f"Errore sull'interfaccia '{args.iface}': {e} (monitor mode attiva?)")

    if not seen:
        print("Nessun AP trovato. Prova ad aggiungere --hop con airodump in parallelo, "
              "o avvicinati all'AP / imposta il canale giusto.")
        return
    print(f"{'SSID':24} {'BSSID':18} {'AKM':22} ESITO")
    print("-" * 100)
    for bssid, (ssid, rsn) in sorted(seen.items(), key=lambda x: x[1][0]):
        akm = ",".join(rsn["akms"]) if rsn and rsn["akms"] else "-"
        print(f"{ssid[:23]:24} {bssid:18} {akm[:21]:22} {verdict(rsn)}")


if __name__ == "__main__":
    main()
