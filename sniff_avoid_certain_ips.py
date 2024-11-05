from scapy.all import sniff, IP, TCP

# IP addresses to ignore in the alert
IGNORE_IPS = {"192.168.203.230", "192.168.203.67","192.168.203.171"}

# Function to check if packet involves IPs not in IGNORE_IPS
def alert_packet(packet):
    # Ensure the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if neither source nor destination IP is in the ignored IPs
        if src_ip not in IGNORE_IPS and dst_ip not in IGNORE_IPS:
            # Print only IP and TCP layer details, if available
            if TCP in packet:
                print("IP Layer:", packet[IP].summary())
                print("TCP Layer:", packet[TCP].summary())
            else:
                print("IP Layer:", packet[IP].summary())
            print("########")  # Separator between packets

# Start sniffing on the network
print("Sniffer started")
sniff(filter="ip", prn=alert_packet)