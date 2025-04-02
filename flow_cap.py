import sys
import time
from scapy.all import PcapReader, sniff
from collections import defaultdict
import pandas as pd
from datetime import datetime

# Function to calculate flow metrics
def calculate_flow_metrics(flow_key, packets):
    src_ip, dst_ip, proto = flow_key
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time
    packet_count = len(packets)
    byte_count = sum(len(pkt) for pkt in packets)
    avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
    max_packet_size = max(len(pkt) for pkt in packets)
    min_packet_size = min(len(pkt) for pkt in packets)
    
    # Inter-arrival times
    inter_arrival_times = [packets[i].time - packets[i-1].time for i in range(1, packet_count)]
    avg_inter_arrival = sum(inter_arrival_times) / len(inter_arrival_times) if inter_arrival_times else 0
    max_idle_time = max(inter_arrival_times) if inter_arrival_times else 0

    # TCP-specific flags and port information
    syn_count = ack_count = fin_count = rst_count = 0
    unique_src_ports = set()
    unique_dst_ports = set()

    for pkt in packets:
        if 'TCP' in pkt:
            flags = pkt['TCP'].flags
            if 'S' in flags: syn_count += 1
            if 'A' in flags: ack_count += 1
            if 'F' in flags: fin_count += 1
            if 'R' in flags: rst_count += 1

            unique_src_ports.add(pkt['TCP'].sport)
            unique_dst_ports.add(pkt['TCP'].dport)
        elif 'UDP' in pkt:
            unique_src_ports.add(pkt['UDP'].sport)
            unique_dst_ports.add(pkt['UDP'].dport)

    flow_metrics = {
        'timestamp': datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': proto,
        'start_time': start_time,
        'end_time': end_time,
        'duration': duration,
        'packet_count': packet_count,
        'byte_count': byte_count,
        'avg_packet_size': avg_packet_size,
        'max_packet_size': max_packet_size,
        'min_packet_size': min_packet_size,
        'avg_inter_arrival': avg_inter_arrival,
        'max_idle_time': max_idle_time,
        'syn_count': syn_count,
        'ack_count': ack_count,
        'fin_count': fin_count,
        'rst_count': rst_count,
        'unique_src_ports': len(unique_src_ports),
        'unique_dst_ports': len(unique_dst_ports),
    }

    return flow_metrics

# Function to save flows to CSV
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

# Function to process a PCAP file in a stream
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
                        proto = pkt['IP'].proto

                        # Flow key without considering ports
                        flow_key = (src_ip, dst_ip, proto)
                        flows[flow_key].append(pkt)

                        packet_count += 1

                    # Periodically save flows
                    if packet_count % 1000 == 0:
                        append_flows_to_csv(flows, output_file)
                        flows.clear()

                except Exception as e:
                    print(f"Error processing packet: {e}")

            # Save remaining flows
            if flows:
                append_flows_to_csv(flows, output_file)

    except MemoryError:
        print(f"Memory error while processing file: {pcap_file}")
    except Exception as e:
        print(f"Error while processing PCAP file: {e}")

# Function to process packets online
def process_packet_online(pkt, flows, output_file):
    try:
        if 'IP' in pkt:
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            proto = pkt['IP'].proto

            flow_key = (src_ip, dst_ip, proto)
            flows[flow_key].append(pkt)

        # Save flows if there are too many in memory
        if len(flows) > 1000:
            append_flows_to_csv(flows, output_file)
            flows.clear()

    except Exception as e:
        print(f"Error processing online packet: {e}")

# Function to start capturing packets online
def run_online_capture(interface, output_file):
    flows = defaultdict(list)
    print(f"Sniffing on interface: {interface}")
    sniff(iface=interface, prn=lambda pkt: process_packet_online(pkt, flows, output_file), timeout=10)

    # Save remaining flows
    if flows:
        append_flows_to_csv(flows, output_file)

# Main function
if __name__ == "__main__":
    output_file = 'network_flows.csv'

    # Check if CSV file exists, if not - create headers
    try:
        with open(output_file, 'x') as f:
            header = [
                'timestamp', 'src_ip', 'dst_ip', 'protocol',
                'start_time', 'end_time', 'duration', 'packet_count', 'byte_count',
                'avg_packet_size', 'max_packet_size', 'min_packet_size',
                'avg_inter_arrival', 'max_idle_time', 'syn_count', 'ack_count',
                'fin_count', 'rst_count', 'unique_src_ports', 'unique_dst_ports'
            ]
            f.write(','.join(header) + '\n')
    except FileExistsError:
        pass  # File already exists

    # Check arguments
    if len(sys.argv) == 2:
        argument = sys.argv[1]
        if argument.endswith(".pcap"):
            process_pcap_stream(argument, output_file)
        else:
            interface = argument
            while True:
                run_online_capture(interface, output_file)
                time.sleep(1)
    else:
        print("Usage: python flow_cap.py [plik.pcap | interfejs]")
        sys.exit(1)
