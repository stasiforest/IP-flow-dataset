import sys
import time
from scapy.all import PcapReader, sniff
from collections import defaultdict
import pandas as pd


from datetime import datetime

# Function to calculate additional flow parameters
def calculate_flow_metrics(flow_key, packets):
    src_ip, dst_ip, src_port, dst_port, proto = flow_key
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time
    packet_count = len(packets)
    byte_count = sum(len(pkt) for pkt in packets)
    avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
    max_packet_size = max(len(pkt) for pkt in packets)

    # Formatting timestamp based on start_time
    timestamp = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')

    # Additional TCP metrics
    syn_count = ack_count = fin_count = rst_count = 0
    first_flag = last_flag = None
    inter_arrival_times = []

    for i in range(1, packet_count):
        inter_arrival_times.append(packets[i].time - packets[i-1].time)

    avg_inter_arrival = sum(inter_arrival_times) / len(inter_arrival_times) if inter_arrival_times else 0
    max_idle_time = max(inter_arrival_times) if inter_arrival_times else 0

    for i, pkt in enumerate(packets):
        if proto == 'TCP':
            flags = pkt['TCP'].flags
            if i == 0:
                first_flag = flags
            if i == packet_count - 1:
                last_flag = flags

            if 'S' in flags:
                syn_count += 1
            if 'A' in flags:
                ack_count += 1
            if 'F' in flags:
                fin_count += 1
            if 'R' in flags:
                rst_count += 1

    first_mac_src = packets[0].src
    first_mac_dst = packets[0].dst

    flow_metrics = {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'start_time': start_time,
        'end_time': end_time,
        'duration': duration,
        'packet_count': packet_count,
        'byte_count': byte_count,
        'avg_packet_size': avg_packet_size,
        'max_packet_size': max_packet_size,
        'avg_inter_arrival': avg_inter_arrival,
        'max_idle_time': max_idle_time,
        'first_flag': first_flag,
        'last_flag': last_flag,
        'syn_count': syn_count,
        'ack_count': ack_count,
        'fin_count': fin_count,
        'rst_count': rst_count,
        'first_mac_src': first_mac_src,
        'first_mac_dst': first_mac_dst,
    }

    return flow_metrics



# Function for saving flows to a CSV file (appending to an existing file)
def append_flows_to_csv(flows, output_file):
    flow_data = []

    for flow_key, packets in flows.items():
        try:
            flow_metrics = calculate_flow_metrics(flow_key, packets)
            flow_data.append(flow_metrics)
        except Exception as e:
            print(f"Error processing flow {flow_key}: {e}")

    if flow_data:
        df = pd.DataFrame(flow_data)
        df.to_csv(output_file, mode='a', header=False, index=False)
        print(f'Dopisywanie przepływów do pliku: {output_file}')


# Function to process a PCAP file in a stream, processing packets sequentially
def process_pcap_stream(pcap_file, output_file):
    flows = defaultdict(list)
    try:
        with PcapReader(pcap_file) as pcap_reader:
            packet_count = 0
            for pkt in pcap_reader:
                try:
                    if 'IP' in pkt:
                        src_ip = pkt['IP'].src
                        dst_ip = pkt['IP'].dst
                        if 'TCP' in pkt:
                            src_port = pkt['TCP'].sport
                            dst_port = pkt['TCP'].dport
                            proto = 'TCP'
                        elif 'UDP' in pkt:
                            src_port = pkt['UDP'].sport
                            dst_port = pkt['UDP'].dport
                            proto = 'UDP'
                        else:
                            continue

                        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                        flows[flow_key].append(pkt)

                        packet_count += 1

                    # Save flows to a file periodically so you don't have to keep everything in memory
                    if packet_count % 1000 == 0:
                        append_flows_to_csv(flows, output_file)
                        flows.clear()

                except Exception as e:
                    print(f"Error processing packet: {e}")

            # Save the remaining flows at the end
            if flows:
                append_flows_to_csv(flows, output_file)


    except MemoryError:
        print(f"Memory error while processing file: {pcap_file}")
    except Exception as e:
        print(f"Error while processing PCAP file: {e}")

# Function for processing packets from the Ethernet interface in online mode
def process_packet_online(pkt, flows, output_file):
    try:
        if 'IP' in pkt:
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            if 'TCP' in pkt:
                src_port = pkt['TCP'].sport
                dst_port = pkt['TCP'].dport
                proto = 'TCP'
            elif 'UDP' in pkt:
                src_port = pkt['UDP'].sport
                dst_port = pkt['UDP'].dport
                proto = 'UDP'
            else:
                return

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            flows[flow_key].append(pkt)

        # If the number of packages in memory exceeds 1000, save to file
        if len(flows) > 1000:
            append_flows_to_csv(flows, output_file)
            flows.clear()


    except Exception as e:
        print(f"Error processing online packet: {e}")

# Function to start online mode (capturing packets from the interface)
def run_online_capture(interface, output_file):
    flows = defaultdict(list)
    print(f"Sniffing on interface: {interface}")
    sniff(iface=interface, prn=lambda pkt: process_packet_online(pkt, flows, output_file), timeout=10)

    # Save the remaining flows at the end
    if flows:
        append_flows_to_csv(flows, output_file)

# The main
if __name__ == "__main__":
    output_file = 'network_flows.csv'

    # Check if CSV file exists, if not - create headers
    try:
        with open(output_file, 'x') as f:
            header = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'start_time', 'end_time', 'duration', 
                      'packet_count', 'byte_count', 'avg_packet_size', 'max_packet_size', 'avg_inter_arrival', 
                      'max_idle_time', 'first_flag', 'last_flag', 'syn_count', 'ack_count', 'fin_count', 
                      'rst_count', 'first_mac_src', 'first_mac_dst']


            
            f.write(','.join(header) + '\n')
    except FileExistsError:
        pass  # File already exists, continue adding data

    # Check if the argument is a PCAP file or a network interface
    if len(sys.argv) == 2:
        argument = sys.argv[1]
        if argument.endswith(".pcap"):
            # Offline mode - PCAP file analysis
            pcap_file = argument
            process_pcap_stream(pcap_file, output_file)
        else:
            # Online mode - capture on interface
            interface = argument
            while True:
                run_online_capture(interface, output_file)
                time.sleep(1)  # Break between sniffing sessions

    else:
        print("Usage: python flow_cap.py [plik.pcap | interfejs]")
        sys.exit(1)
