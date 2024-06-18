from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, Raw

# Function to replace email addresses in packet payloads
def replace_string_in_pcapng(input_file, old_string, new_string, output_file):
    # Read the pcapng file
    packets = rdpcap(input_file)

    for packet in packets:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Replace the old string address with the new string address
            new_payload = payload.replace(old_string.encode(), new_string.encode())
            packet[Raw].load = new_payload

            # Recalculate checksums for IP and TCP/UDP layers
            if packet.haslayer(IP):
                del packet[IP].chksum
            if packet.haslayer(TCP):
                del packet[TCP].chksum
            elif packet.haslayer(UDP):
                del packet[UDP].chksum

    # Save the modified packets to a new file
    wrpcap(output_file, packets)

# Input parameters
input_file = input("Enter the input pcapng file name: ")
old_string = input("Enter the string to replace: ")
new_string = input("Enter the new string: ")
output_file = input("Enter the output pcapng file name: ")

# Replace string in the pcapng file
replace_string_in_pcapng(input_file, old_string, new_string, output_file)

print(f"string replaced and saved to {output_file}")

