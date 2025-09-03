from scapy.all import rdpcap, IP, TCP, UDP, IPv6
import pandas as pd
import numpy as np
from collections import defaultdict


def extract_flow_features(pcap_file, output_csv):
    packets = rdpcap(pcap_file)
    print(f"Total packets in pcap: {len(packets)}")

    flows = defaultdict(list)
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        # Handle IPv6
        elif IPv6 in pkt:
            proto = pkt[IPv6].nh  # "Next Header" field
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        else:
            continue  # Skip non-IP packets

        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

        flow_key = (src_ip, sport, dst_ip, dport, proto)

        timestamp = pkt.time
        size = len(pkt)

        flows[flow_key].append((timestamp, size))
    flow_data=[]
    for key,pkts in flows.items():
        src_ip, sport, dst_ip, dport, proto = key
        pkts = sorted(pkts, key=lambda x:x[0])

        pkt_times = [p[0] for p in pkts]
        pkt_sizes = [p[1] for p in pkts]

        flow_duration = pkt_times[-1] - pkt_times[0] if len(pkt_times) > 1 else 0
        piats = np.diff(pkt_times) if len(pkt_times) > 1 else [0.0]
        piats_float = [float(x) for x in piats]
        flow_data.append({
            'src_port': sport,
            'dst_port': dport,
            'proto': proto,
            'pktTotalCount': len(pkts),
            'octetTotalCount': sum(pkt_sizes),
            'avg_ps': np.mean(pkt_sizes),
            'std_dev_ps': np.std(pkt_sizes),
            'flowDuration': flow_duration,
            'avg_piat': np.mean(piats_float),
            'std_dev_piat': np.std(piats_float),
        })
    df = pd.DataFrame(flow_data)
    df.to_csv(output_csv, index=False)
    print(f"Saved {len(df)} flows to {output_csv}")


# input_pcap = "data/raw/sample_data.pcap"
# output_csv = "data/processed/classifer.csv"
# extract_flow_features(input_pcap, output_csv)