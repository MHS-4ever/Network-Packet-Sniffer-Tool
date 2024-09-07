from scapy.all import sniff

# Callback function to process captured packets
def process_packet(packet):
    # Check if packet has an IP layer
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Display TCP/UDP payload data if available
        if packet.haslayer('Raw'):
            payload_data = packet.getlayer('Raw').load
            print(f"Payload: {payload_data}")

        print('-' * 50)

# Sniff packets on all interfaces
sniff(prn=process_packet, count=10)
