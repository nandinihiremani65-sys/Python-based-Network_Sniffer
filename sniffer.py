from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

packet_count = 0

def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    if TCP in packet:
        protocol = "TCP"
        details = f"{packet[TCP].sport} -> {packet[TCP].dport}"

    elif UDP in packet:
        protocol = "UDP"
        details = f"{packet[UDP].sport} -> {packet[UDP].dport}"

    elif ICMP in packet:
        protocol = "ICMP"
        details = "Ping traffic"

    else:
        protocol = f"IP protocol {packet[IP].proto}"
        details = "Other IP traffic"

    print("\n==============================")
    print("PACKET NUMBER:", packet_count)
    print("==============================")
    print("Source IP      :", source_ip)
    print("Destination IP :", destination_ip)
    print("Protocol       :", protocol)
    print("Packet Size    :", packet_size, "bytes")
    print("Details        :", details)

    if DNS in packet and packet[DNS].qd:
        query = packet[DNS].qd.qname
        print("DNS Query      :", query.decode(errors="replace"))


print("================================")
print(" PYTHON NETWORK PACKET SNIFFER")
print("================================")
print("Capturing 30 IPv4 packets...")
print("Press Ctrl+C to stop.")

try:
    sniff(
        filter="ip",
        prn=analyze_packet,
        count=0,
        store=False
    )

except PermissionError:
    print("Permission denied. Run using sudo.")

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

print("\nTotal packets captured:", packet_count)
print("Program completed.")
