#!/usr/bin/env python3
"""Deep packet analysis for nginx capture CSV. Supports txt, json, csv output."""

import pandas as pd
import numpy as np
import json
import sys
import os
from datetime import datetime
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


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

    def _get_line_boundaries(self, f, chunk_size, total_size):
        """Find chunk boundaries aligned to line endings."""
        boundaries = [0]
        pos = chunk_size
        while pos < total_size:
            f.seek(pos)
            f.readline()  # skip partial line
            boundaries.append(f.tell())
            pos += chunk_size
        boundaries.append(total_size)
        return list(zip(boundaries[:-1], boundaries[1:]))

    def _parse_file_chunk(self, start, end, cols, chunk_idx):
        """Parse a byte-range chunk directly from file."""
        rows = []
        skipped = []
        line_num = chunk_idx * 100000  # approximate for error reporting
        with open(self.csv_path) as f:
            f.seek(start)
            if start != 0:
                f.readline()  # skip partial line at start
            while f.tell() < end:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    parts = line.split(',')
                    if len(parts) != len(cols):
                        raise ValueError(f"expected {len(cols)} cols, got {len(parts)}")
                    row = dict(zip(cols, parts))
                    row['timestamp_ns'] = int(row['timestamp_ns'])
                    row['delta_time'] = float(row['delta_time'])
                    row['size'] = int(row['size'])
                    row['src_port'] = int(row['src_port'])
                    row['dst_port'] = int(row['dst_port'])
                    rows.append(row)
                    line_num += 1
                except Exception as e:
                    skipped.append({'line': line_num, 'error': str(e), 'raw': line[:80]})
        return rows, skipped

    def load_data(self):
        """Load CSV with seek-based parallel chunked parsing."""
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"CSV not found: {self.csv_path}")
        if not os.path.isfile(self.csv_path):
            raise FileNotFoundError(f"CSV not found: {self.csv_path}")

        if os.path.getsize(self.csv_path) == 0:
            raise ValueError("CSV file is empty")

        cols = [
            'seq', 'col1', 'col2', 'timestamp_ns', 'rel_time', 'delta_time',
            'src_ip', 'dst_ip', 'size', 'proto', 'src_port', 'dst_port',
            'flags', 'seq_num', 'ack_num'
        ]

        file_size = os.path.getsize(self.csv_path)
        total_lines = sum(1 for _ in open(self.csv_path))
        chunk_size = max(10 * 1024 * 1024, file_size // 8)  # ~8 chunks, 10MB min

        print(f"Parsing {total_lines} rows with seek-based parallel chunks...")

        all_rows = []
        start_time = time.time()

        with open(self.csv_path) as f:
            boundaries = self._get_line_boundaries(f, chunk_size, file_size)

        print(f"Created {len(boundaries)} chunks")

        with ThreadPoolExecutor() as executor:
            futures = {}
            for idx, (start, end) in enumerate(boundaries):
                futures[executor.submit(self._parse_file_chunk, start, end, cols, idx)] = idx

            for future in tqdm(as_completed(futures), total=len(boundaries), desc="Parsing chunks"):
                rows, skipped = future.result()
                all_rows.extend(rows)
                for s in skipped:
                    self.skipped_rows += 1
                    self.skipped_details.append(s)

        if not all_rows:
            raise ValueError("No valid rows parsed")

        parse_time = time.time() - start_time
        print(f"Parsed in {parse_time:.2f}s ({len(all_rows)/parse_time:.0f} rows/sec)")

        self.df = pd.DataFrame(all_rows)
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp_ns'], unit='ns')
        self.df['size_kb'] = self.df['size'] / 1024

        required = ['timestamp_ns', 'delta_time', 'size', 'src_ip', 'dst_ip', 'flags']
        missing = [c for c in required if c not in self.df.columns]
        if missing:
            raise ValueError(f"Missing required columns after cleaning: {missing}")

    def analyze_latency(self):
        delta = self.df['delta_time']
        stats = delta.describe()
        self.results['latency'] = {
            'mean': float(stats['mean']),
            'median': float(stats['50%']),
            'std': float(stats['std']),
            'min': float(stats['min']),
            'max': float(stats['max']),
            'p95': float(delta.quantile(0.95)),
            'p99': float(delta.quantile(0.99)),
            'burst_count': int((delta < 0.0001).sum()),
            'burst_pct': float((delta < 0.0001).sum() / len(delta) * 100)
        }

    def analyze_throughput(self):
        total_bytes = int(self.df['size'].sum())
        total_mb = total_bytes / (1024 * 1024)
        time_span = (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds() or 0.000001
        self.results['throughput'] = {
            'total_packets': int(len(self.df)),
            'total_bytes': total_bytes,
            'total_mb': round(total_mb, 4),
            'capture_span_s': round(time_span, 6),
            'throughput_mbps': round(total_mb / time_span * 8, 2),
            'pps': int(len(self.df) / time_span),
            'peak_100ms_kb': round(self.df.set_index('timestamp').rolling('100ms')['size'].sum().max() / 1024, 2)
        }

    def analyze_tcp_flags(self):
        flag_counts = self.df['flags'].value_counts().to_dict()
        pct = {k: round(v / len(self.df) * 100, 2) for k, v in flag_counts.items()}
        psh = self.df[self.df['flags'].str.contains('PSH', na=False)]
        ack_only = self.df[self.df['flags'] == 'ACK']
        self.results['tcp_flags'] = {
            'flag_counts': flag_counts,
            'flag_pct': pct,
            'psh_count': int(len(psh)),
            'psh_pct': round(len(psh) / len(self.df) * 100, 2),
            'psh_avg_size': round(psh['size'].mean(), 1) if len(psh) else 0,
            'ack_only_count': int(len(ack_only)),
            'ack_only_pct': round(len(ack_only) / len(self.df) * 100, 2)
        }

    def analyze_connections(self):
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
        pairs = self.df.groupby(['src_ip', 'dst_ip']).agg({'size': ['count', 'sum']})
        pairs.columns = ['packets', 'bytes']
        pairs = pairs.sort_values('bytes', ascending=False)
        self.results['direction'] = {'ip_pairs': [{'src': src, 'dst': dst, 'packets': int(row['packets']), 'bytes_kb': round(float(row['bytes']) / 1024, 1)} for (src, dst), row in pairs.iterrows()]}

    def run(self):
        self.load_data()
        print("Running parallel analysis...")

        analysis_start = time.time()
        analyses = [
            ('latency', self.analyze_latency),
            ('throughput', self.analyze_throughput),
            ('tcp_flags', self.analyze_tcp_flags),
            ('connections', self.analyze_connections),
            ('direction', self.analyze_direction)
        ]

        with ThreadPoolExecutor() as executor:
            futures = {}
            start_times = {}
            for name, fn in analyses:
                future = executor.submit(fn)
                futures[future] = name
                start_times[future] = time.time()

            completed = 0
            total = len(analyses)
            phase_times = []

            for future in tqdm(as_completed(futures), total=total, desc="Analysis"):
                name = futures[future]
                phase_start = start_times[future]
                try:
                    future.result()
                    phase_time = time.time() - phase_start
                    phase_times.append(phase_time)
                    completed += 1
                    total_elapsed = time.time() - analysis_start
                    remaining_phases = total - completed
                    avg_phase_time = sum(phase_times) / len(phase_times)
                    eta = avg_phase_time * remaining_phases if remaining_phases > 0 else 0
                    print(f"  ✓ {name} ({phase_time:.2f}s) | total: {total_elapsed:.1f}s, eta: {eta:.1f}s")
                except Exception as e:
                    print(f"  ✗ {name} failed: {e}")

        analysis_time = time.time() - analysis_start
        print(f"Analysis complete in {analysis_time:.2f}s")

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