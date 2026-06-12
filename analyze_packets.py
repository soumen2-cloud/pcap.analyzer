#!/usr/bin/env python3
"""Deep packet analysis for nginx capture CSV. Supports txt, json, csv output."""

import pandas as pd
import numpy as np
import json
import sys
import os
from datetime import datetime
from tqdm import tqdm


class PacketAnalyzer:
    def __init__(self, csv_path, output_format='txt', output_file=None):
        self.csv_path = csv_path
        self.output_format = output_format.lower()
        self.output_file = output_file
        self.results = {}
        self.df = None
        self.skipped_rows = 0
        self.skipped_details = []

        if self.output_format not in ['txt', 'json', 'csv']:
            raise ValueError(f"Invalid format: {output_format}. Use txt, json, or csv.")

    def load_data(self):
        # Load CSV data with error handling and type coercion
        # Skips malformed rows, collects error details, validates required columns
        # Converts timestamp to datetime and calculates size in KB
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV not found: {self.csv_path}")

        if os.path.getsize(self.csv_path) == 0:
            raise ValueError("CSV file is empty")

        cols = [
            'seq', 'col1', 'col2', 'timestamp_ns', 'rel_time', 'delta_time',
            'src_ip', 'dst_ip', 'size', 'proto', 'src_port', 'dst_port',
            'flags', 'seq_num', 'ack_num'
        ]

        rows = []
        total_lines = sum(1 for _ in open(self.csv_path))

        print(f"Parsing {total_lines} rows...")
        with open(self.csv_path) as f:
            for i, line in enumerate(tqdm(f, total=total_lines, unit='rows')):
                line = line.strip()
                if not line:
                    continue
                try:
                    parts = line.split(',')
                    if len(parts) != len(cols):
                        raise ValueError(f"expected {len(cols)} cols, got {len(parts)}")
                    row = dict(zip(cols, parts))
                    # type coercion
                    row['timestamp_ns'] = int(row['timestamp_ns'])
                    row['delta_time'] = float(row['delta_time'])
                    row['size'] = int(row['size'])
                    row['src_port'] = int(row['src_port'])
                    row['dst_port'] = int(row['dst_port'])
                    rows.append(row)
                except Exception as e:
                    self.skipped_rows += 1
                    self.skipped_details.append({'line': i + 1, 'error': str(e), 'raw': line[:80]})

        if not rows:
            raise ValueError("No valid rows parsed")

        self.df = pd.DataFrame(rows)
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp_ns'], unit='ns')
        self.df['size_kb'] = self.df['size'] / 1024

        required = ['timestamp_ns', 'delta_time', 'size', 'src_ip', 'dst_ip', 'flags']
        missing = [c for c in required if c not in self.df.columns]
        if missing:
            raise ValueError(f"Missing required columns after cleaning: {missing}")

    def analyze_latency(self):
        # Compute latency metrics in nanoseconds:
        # - RTT: approximated from mean inter-packet timestamp differences
        # - Delta time: inter-packet arrival statistics
        # - Application latency: estimated processing time (80% of delta time)
        delta = self.df['delta_time']
        sorted_df = self.df.sort_values('timestamp_ns')
        time_diffs = sorted_df['timestamp_ns'].diff().dropna()

        # RTT: round-trip time approximated from timestamp differences
        rtt_ns = time_diffs.mean() if len(time_diffs) > 0 else 0

        # Delta time statistics (inter-packet arrival time)
        delta_stats = delta.describe()

        # Application latency: time spent processing at application layer
        # Approximated as delta time minus estimated network propagation
        # Using 80% of delta time as application processing (network is typically 20%)
        app_latency_ns = delta.mean() * 1e9 * 0.8 if len(delta) > 0 else 0

        self.results['latency'] = {
            'rtt_ns': round(float(rtt_ns), 2),
            'delta_time_mean_ns': round(float(delta_stats['mean']) * 1e9, 2),
            'delta_time_median_ns': round(float(delta_stats['50%']) * 1e9, 2),
            'delta_time_std_ns': round(float(delta_stats['std']) * 1e9, 2),
            'delta_time_min_ns': round(float(delta_stats['min']) * 1e9, 2),
            'delta_time_max_ns': round(float(delta_stats['max']) * 1e9, 2),
            'delta_time_p95_ns': round(float(delta.quantile(0.95)) * 1e9, 2),
            'delta_time_p99_ns': round(float(delta.quantile(0.99)) * 1e9, 2),
            'application_latency_mean_ns': round(float(app_latency_ns), 2),
            'burst_count': int((delta < 0.0001).sum()),
            'burst_percentage': round(float((delta < 0.0001).sum() / len(delta) * 100), 2)
        }

    def analyze_traffic_categories(self):
        # Classify packets by TCP flags and size into categories:
        # - Handshake: SYN/SYN-ACK packets
        # - Connection: SYN or small ACK packets
        # - Data transfer: PSH or large ACK packets
        # - Control: pure ACK/FIN/RST control packets
        # Calculates byte counts and percentages for each category
        total_bytes = int(self.df['size'].sum())

        # Handshake: SYN, SYN-ACK, ACK sequences
        handshake_flags = ['SYN', 'SYN-ACK']
        handshake_mask = self.df['flags'].isin(handshake_flags)
        handshake_bytes = int(self.df[handshake_mask]['size'].sum())

        # Connection establishment: contains SYN or ACK with small sizes (< 100 bytes typically)
        connection_mask = (self.df['flags'].str.contains('SYN', na=False) |
                          ((self.df['flags'] == 'ACK') & (self.df['size'] < 100)))
        connection_bytes = int(self.df[connection_mask]['size'].sum())

        # Data transfer: PSH flag or larger packets (> 100 bytes with ACK)
        data_mask = (self.df['flags'].str.contains('PSH', na=False) |
                    ((self.df['size'] >= 100) & ~self.df['flags'].str.contains('SYN', na=False)))
        data_bytes = int(self.df[data_mask]['size'].sum())

        # Control traffic: pure ACKs, FIN, RST, and other control packets
        control_mask = (self.df['flags'].isin(['ACK', 'FIN', 'RST', 'FIN-ACK', 'RST-ACK']) &
                       (self.df['size'] < 100))
        control_bytes = int(self.df[control_mask]['size'].sum())

        # Adjust to ensure total adds up (handle overlaps)
        categorized_bytes = handshake_bytes + data_bytes + control_bytes
        connection_bytes = min(connection_bytes, total_bytes - categorized_bytes + connection_bytes)

        # Calculate percentages
        if total_bytes > 0:
            handshake_percentage = round((handshake_bytes / total_bytes) * 100, 2)
            connection_percentage = round((connection_bytes / total_bytes) * 100, 2)
            data_percentage = round((data_bytes / total_bytes) * 100, 2)
            control_percentage = round((control_bytes / total_bytes) * 100, 2)
        else:
            handshake_percentage = connection_percentage = data_percentage = control_percentage = 0.0

        self.results['traffic_categories'] = {
            'handshake': {'bytes': handshake_bytes, 'percentage': handshake_percentage},
            'connection': {'bytes': connection_bytes, 'percentage': connection_percentage},
            'data_transfer': {'bytes': data_bytes, 'percentage': data_percentage},
            'control': {'bytes': control_bytes, 'percentage': control_percentage},
            'total_bytes': total_bytes
        }

    def analyze_throughput(self):
        # Calculate throughput excluding headers versus raw capture
        # Data packet identification: PSH flag or packets >= 100 bytes without SYN
        # Subtracts 4-byte FCS from Ethernet frames
        # header variable includes Ethernet (14) + IP (20) + TCP (20) = 54 bytes per packet
        # Computes multiple throughput metrics and interframe gap statistics
        data_mask = (self.df['flags'].str.contains('PSH', na=False) |
                    ((self.df['size'] >= 100) & ~self.df['flags'].str.contains('SYN', na=False)))
        data_df = self.df[data_mask]

        # Calculate data bytes (Ethernet frame minus 4-byte FCS)
        # Assuming size field contains Ethernet frame size, subtract FCS
        data_bytes_raw = int(data_df['size'].sum())  # raw captured bytes
        data_bytes_no_fcs = data_bytes_raw - (len(data_df) * 4)  # subtract 4-byte FCS per frame

        # Calculate header bytes: Ethernet (14) + IP (20) + TCP (20 assuming no options) = 54 bytes
        header = len(data_df) * 54
        data_bytes_with_header = data_bytes_no_fcs
        data_bytes_without_header = data_bytes_no_fcs - header

        # Calculate interframe gaps (average time between consecutive packets)
        sorted_df = self.df.sort_values('timestamp_ns')
        time_diffs = sorted_df['timestamp_ns'].diff().dropna() / 1e9  # convert ns to seconds
        avg_ifg_us = round(time_diffs.mean() * 1e6, 2) if len(time_diffs) > 0 else 0

        time_span = (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds() or 0.000001

        self.results['throughput'] = {
            'total_packets': int(len(self.df)),
            'data_packets': int(len(data_df)),
            'capture_span_s': round(time_span, 2),
            'data_bytes_raw': data_bytes_raw,
            'data_bytes_no_fcs': data_bytes_no_fcs,
            'data_bytes_with_header': data_bytes_with_header,
            'data_bytes_without_header': max(0, data_bytes_without_header),
            'throughput_raw_mbps': round(data_bytes_raw / time_span / (1024*1024) * 8, 2),
            'throughput_no_fcs_mbps': round(data_bytes_no_fcs / time_span / (1024*1024) * 8, 2),
            'throughput_with_header_mbps': round(data_bytes_with_header / time_span / (1024*1024) * 8, 2),
            'throughput_without_header_mbps': round(max(0, data_bytes_without_header) / time_span / (1024*1024) * 8, 2),
            'pps': int(len(self.df) / time_span),
            'peak_100ms_kb': round(self.df.set_index('timestamp').rolling('100ms')['size'].sum().max() / 1024, 2),
            'avg_interframe_gap_us': avg_ifg_us
        }

    def analyze_tcp_flags(self):
        # Count and analyze TCP flag distributions
        # Identifies PSH (data push) and ACK-only packets
        # Calculates average sizes for data and control packets
        flag_counts = self.df['flags'].value_counts()
        percentage = {k: round(v / len(self.df) * 100, 2) for k, v in flag_counts.items()}
        psh = self.df[self.df['flags'].str.contains('PSH', na=False)]
        ack_only = self.df[self.df['flags'] == 'ACK']
        self.results['tcp_flags'] = {
            'flag_counts': flag_counts.to_dict(),
            'flag_percentage': percentage,
            'psh_count': int(len(psh)),
            'psh_percentage': round(len(psh) / len(self.df) * 100, 2),
            'psh_avg_size': round(psh['size'].mean(), 1) if len(psh) else 0,
            'ack_only_count': int(len(ack_only)),
            'ack_only_percentage': round(len(ack_only) / len(self.df) * 100, 2)
        }

    def analyze_sequence_numbers(self):
        # Track sequence and acknowledgment numbers per flow
        # Detects retransmissions (duplicate seq) and out-of-order delivery
        # Calculates average window size and gap between seq numbers
        self.df['flow'] = self.df.apply(
            lambda r: tuple(sorted([f"{r['src_ip']}:{r['src_port']}", f"{r['dst_ip']}:{r['dst_port']}"])), axis=1
        )
        flows = self.df.groupby('flow')
        retransmissions = 0
        out_of_order = 0
        seq_gaps = []
        window_sizes = []
        for _, group in flows:
            group = group.sort_values('timestamp_ns')
            seqs = group['seq_num'].astype(int)
            acks = group['ack_num'].astype(int)
            # retransmissions: duplicate sequence numbers
            retransmissions += seqs.duplicated().sum()
            # out-of-order: seq numbers not strictly increasing
            out_of_order += (seqs.diff().dropna() <= 0).sum()
            # gaps between consecutive seq numbers
            gaps = seqs.diff().dropna()
            seq_gaps.extend(gaps[gaps > 0].tolist())
            # approximate window from ack-seq difference
            window = (acks - seqs).abs()
            window_sizes.extend(window.tolist())
        avg_gap = float(np.mean(seq_gaps)) if seq_gaps else 0
        avg_window = float(np.mean(window_sizes)) if window_sizes else 0
        self.results['sequence_numbers'] = {
            'retransmissions': int(retransmissions),
            'out_of_order': int(out_of_order),
            'avg_seq_gap': round(avg_gap, 1),
            'avg_window_size': round(avg_window, 1)
        }

    def analyze_connections(self):
        # Group packets into bidirectional flows using sorted IP:port pairs
        # Calculates flow duration, packets per second, and top flows by bytes
        self.df['flow'] = self.df.apply(
            lambda r: tuple(sorted([f"{r['src_ip']}:{r['src_port']}", f"{r['dst_ip']}:{r['dst_port']}"])), axis=1
        )
        flows = self.df.groupby('flow').agg({'size': ['count', 'sum'], 'timestamp': ['min', 'max']})
        flows.columns = ['packets', 'bytes', 'start', 'end']
        flows['duration'] = (flows['end'] - flows['start']).dt.total_seconds()
        flows['pps'] = flows['packets'] / flows['duration'].replace(0, 0.001)
        top = flows.nlargest(5, 'bytes')
        top_flows = [{'flow': f"{flow[0]} <-> {flow[1]}", 'packets': int(row['packets']), 'bytes_kb': round(row['bytes'] / 1024, 1)} for flow, row in top.iterrows()]
        self.results['connections'] = {
            'unique_flows': int(len(flows)),
            'mean_duration_s': round(flows['duration'].mean(), 6),
            'max_duration_s': round(flows['duration'].max(), 6),
            'mean_packets': round(flows['packets'].mean(), 1),
            'max_packets': int(flows['packets'].max()),
            'top_5_flows': top_flows
        }

    def analyze_direction(self):
        # Analyze traffic direction by grouping source-destination IP pairs
        # Sorts by total bytes to identify dominant communication paths
        pairs = self.df.groupby(['src_ip', 'dst_ip']).agg({'size': ['count', 'sum']})
        pairs.columns = ['packets', 'bytes']
        pairs = pairs.sort_values('bytes', ascending=False)
        self.results['direction'] = {'ip_pairs': [{'src': src, 'dst': dst, 'packets': int(row['packets']), 'bytes_kb': round(row['bytes'] / 1024, 1)} for (src, dst), row in pairs.iterrows()]}

    def run(self):
        self.load_data()
        print("Running analysis...")
        for fn in [self.analyze_latency, self.analyze_traffic_categories, self.analyze_throughput, self.analyze_tcp_flags, self.analyze_sequence_numbers, self.analyze_connections, self.analyze_direction]:
            fn()
        self.results['meta'] = {
            'input_file': self.csv_path,
            'generated': datetime.now().isoformat(),
            'packet_count': int(len(self.df)),
            'skipped_rows': self.skipped_rows,
            'skipped_details': self.skipped_details
        }

    def output(self):
        if self.output_format == 'json':
            content = json.dumps(self.results, indent=2)
        elif self.output_format == 'csv':
            rows = []
            for section, data in self.results.items():
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, (int, float, str)):
                            rows.append({'section': section, 'metric': k, 'value': v})
            content = pd.DataFrame(rows).to_csv(index=False)
        else:
            lines = [f"Packet Analysis — {self.results['meta']['input_file']}\n"]
            for section, data in self.results.items():
                if section == 'meta':
                    continue
                lines.append(f"\n{'='*50}\n{section.upper()}\n{'='*50}")
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, list):
                            lines.append(f"{k}:")
                            for item in v:
                                lines.append(f"  {item}")
                        else:
                            lines.append(f"{k}: {v}")
            if self.skipped_rows:
                lines.append(f"\n{'='*50}\nSKIPPED ROWS\n{'='*50}")
                lines.append(f"Total skipped: {self.skipped_rows}")
                for d in self.skipped_details[:10]:
                    lines.append(f"  line {d['line']}: {d['error']} | {d['raw']}")
                if len(self.skipped_details) > 10:
                    lines.append(f"  ... and {len(self.skipped_details)-10} more")
            content = '\n'.join(lines)

        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(content)
            print(f"Written: {self.output_file}")
        else:
            print(content)


def print_help():
    print("""analyze_packets.py — deep nginx packet capture analyzer

USAGE:
  python analyze_packets.py <csv>                    # default txt output
  python analyze_packets.py <csv> txt                # explicit txt
  python analyze_packets.py <csv> json               # json to stdout
  python analyze_packets.py <csv> csv                # csv to stdout
  python analyze_packets.py <csv> json out.json      # json to file
  python analyze_packets.py <csv> csv  out.csv       # csv to file
  python analyze_packets.py <csv> txt  out.txt       # txt to file
  python analyze_packets.py -h|--help                # this help

ARGUMENTS:
  <csv>       input packet capture CSV (required)
  [format]    txt | json | csv   (default: txt)
  [output]    optional filename; if omitted, prints to stdout

DESCRIPTION:
  Parses CSV, skips malformed rows, reports skipped-row stats,
  computes latency/throughput/TCP-flags/connection/direction metrics,
  and emits results in the requested format.""")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print_help()
        sys.exit(0)

    csv_path = sys.argv[1]
    fmt = sys.argv[2] if len(sys.argv) > 2 else 'txt'
    out = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        analyzer = PacketAnalyzer(csv_path, fmt, out)
        analyzer.run()
        analyzer.output()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(2)


if __name__ == '__main__':
    main()