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
        elif IPv6 in pkt:
            proto = pkt[IPv6].nh
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            continue
            
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

        flow_key = (src_ip, sport, dst_ip, dport, proto)

        timestamp = pkt.time
        size = len(pkt)
        tcp_flags = pkt[TCP].flags if TCP in pkt else None

        flows[flow_key].append((timestamp, size, tcp_flags, src_ip, dst_ip, sport, dport))

    flow_data=[]

    for key, pkts in flows.items():
        src_ip, sport, dst_ip, dport, proto = key
        pkts = sorted(pkts, key=lambda x:x[0])

        pkt_times = [p[0] for p in pkts]
        pkt_sizes = [p[1] for p in pkts]
        tcp_flags_list = [p[2] for p in pkts if p[2] is not None]
        src_ports_list = [p[5] for p in pkts]
        dst_ports_list = [p[6] for p in pkts]

        flow_duration = pkt_times[-1] - pkt_times[0] if len(pkt_times) > 1 else 0

        iats = np.diff(pkt_times) if len(pkt_times) > 1 else [0.0]
        iats_float = [float(x) for x in iats]


        fwd_sizes = [size for (_, size, _, sip, _, _, _) in pkts if sip == src_ip]
        bwd_sizes = [size for (_, size, _, sip, _, _, _) in pkts if sip == dst_ip]
        fwd_times = [float(time) for (time, _, _, sip, _, _, _) in pkts if sip == src_ip]
        bwd_times = [float(time) for (time, _, _, sip, _, _, _) in pkts if sip == dst_ip]

        pkt_times = [float(p[0]) for p in pkts]

        fin_flags = sum(1 for f in tcp_flags_list if f & 0x01)  # FIN bit
        syn_flags = sum(1 for f in tcp_flags_list if f & 0x02)  # SYN bit

        total_packets = len(pkts)
        total_bytes = sum(pkt_sizes)
        flow_bytes_per_s = total_bytes / flow_duration if flow_duration > 0 else 0
        flow_packets_per_s = total_packets / flow_duration if flow_duration > 0 else 0
        down_up_ratio = (len(bwd_sizes) / len(fwd_sizes)) if len(fwd_sizes) > 0 else 0

        flow_data.append({
            'Flow Duration': flow_duration,
            'Total Fwd Packet': len(fwd_sizes),
            'Total Length of Fwd Packet': sum(fwd_sizes),
            'Fwd Packet Length Mean': np.mean(fwd_sizes) if fwd_sizes else 0,
            'Bwd Packet Length Mean': np.mean(bwd_sizes) if bwd_sizes else 0,
            'Flow Bytes/s': flow_bytes_per_s,
            'Flow Packets/s': flow_packets_per_s,
            'Flow IAT Mean': np.mean(iats_float),
            'Flow IAT Std': np.std(iats_float),
            'Fwd IAT Mean': np.mean(np.diff(fwd_times)) if len(fwd_times) > 1 else 0,
            'FIN Flag Count': fin_flags,
            'SYN Flag Count': syn_flags,
            'Down/Up Ratio': down_up_ratio,
            'Packet Length Mean': np.mean(pkt_sizes)
        })

    df = pd.DataFrame(flow_data)
    df.to_csv(output_csv, index=False)
    print(f"Saved {len(df)} flows to {output_csv}")
