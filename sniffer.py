from scapy.all import sniff, IP, TCP, UDP, Raw

def process_pkt(pkt):
    # We only care about IP packets for now
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        
        print(f"\nGot Packet: {src} -> {dst} | Protocol: {proto}")

        # Checking for TCP traffic (Web, etc.)
        if pkt.haslayer(TCP):
            print(f"  TCP Port: {pkt[TCP].sport} to {pkt[TCP].dport}")
            
        # Checking for UDP traffic (DNS, Video, etc.)
        elif pkt.haslayer(UDP):
            print(f"  UDP Port: {pkt[UDP].sport} to {pkt[UDP].dport}")

        # If there is any raw data/payload
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            print(f"  Raw Data: {load[:50]}") 

        print("-" * 30)

# Main part of the script
print("--- Starting my packet sniffer ---")

# Using 'ip' filter to see basic traffic
sniff(filter="ip", prn=process_pkt, store=False)