from scapy.all import *
import sys

def PacketHandling(packet, log):
    if packet.haslayer(TCP):
        sourceIP = packet[IP].src
        sourcePort = packet[TCP].sport
        destinationIP = packet[IP].dst
        destinationPort = packet[TCP].dport
        log.write(f"TCP Connection: {sourceIP}:{sourcePort} -> {destinationIP}:{destinationPort}\n")

def main(interface, verbose=False):
    logfile_name = f"LOG_{interface}.txt"
    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                sniff(iface=interface, prn=lambda pkt: PacketHandling(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: PacketHandling(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    main(sys.argv[1], verbose)
