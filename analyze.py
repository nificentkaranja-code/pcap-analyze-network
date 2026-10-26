from scapy.all  import rdpcap, IP, TCP, UDP
def analyze_pcap(file_path):
    """Reads a pcap file and prints source , destination and protocal."""
    try:
        packets = rdpcap(file_path)
        print(f"Total packets captured: {len(packets)}")
        print("-"*40)
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                if TCP in pkt:
                    proto = "TCP"
                elif UDP in pkt:
                    proto = "UDP"
                else:
                    proto = "Other"
                print(f"{src} -> {dst} [{proto}]")
    except FileNotFoundError:
            print(f"Error: Could not find the file '{file_path}'")
    except Exception as e:
            print(f" An error occurred: {e}")
if __name__=="__main__":
    file_to_analyze = input("Enter the pcap file path")
    analyze_pcap(file_to_analyze)
 

