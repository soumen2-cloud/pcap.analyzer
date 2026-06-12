#!/usr/bin/env python3
"""Comprehensive tests for analyze_packets.py"""

import unittest
import tempfile
import os
import json
import pandas as pd
from analyze_packets import PacketAnalyzer


class TestPacketAnalyzer(unittest.TestCase):
    def setUp(self):
        self.valid_csv = 'fcap.csv'

    def test_valid_run_txt(self):
        """Normal execution with txt output."""
        a = PacketAnalyzer(self.valid_csv, 'txt')
        a.run()
        self.assertIn('latency', a.results)
        self.assertIn('throughput', a.results)
        self.assertGreater(a.results['meta']['packet_count'], 0)

    def test_valid_run_json(self):
        """JSON output structure."""
        a = PacketAnalyzer(self.valid_csv, 'json')
        a.run()
        out = json.loads(json.dumps(a.results))
        self.assertIn('tcp_flags', out)
        self.assertIsInstance(out['connections']['unique_flows'], int)

    def test_valid_run_csv(self):
        """CSV output generation."""
        a = PacketAnalyzer(self.valid_csv, 'csv')
        a.run()
        self.assertIn('direction', a.results)

    def test_file_not_found(self):
        """Missing file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            a = PacketAnalyzer('nonexistent.csv')
            a.load_data()

    def test_empty_file(self):
        """Empty file raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write('')
            path = f.name
        try:
            with self.assertRaises(ValueError):
                a = PacketAnalyzer(path)
                a.load_data()
        finally:
            os.unlink(path)

    def test_invalid_format(self):
        """Bad format raises ValueError."""
        with self.assertRaises(ValueError):
            PacketAnalyzer(self.valid_csv, 'xml')

    def test_corrupt_csv(self):
        """Bad CSV content raises ValueError."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write('not,a,valid,csv\n1,2,3')
            path = f.name
        try:
            with self.assertRaises(ValueError):
                a = PacketAnalyzer(path)
                a.load_data()
        finally:
            os.unlink(path)

    def test_missing_columns(self):
        """CSV missing required columns fails."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write('a,b,c\n1,2,3\n')
            path = f.name
        try:
            with self.assertRaises(ValueError):
                a = PacketAnalyzer(path)
                a.load_data()
        finally:
            os.unlink(path)

    def test_json_file_output(self):
        """JSON written to file correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            out_path = f.name
        try:
            a = PacketAnalyzer(self.valid_csv, 'json', out_path)
            a.run()
            a.output()
            self.assertTrue(os.path.exists(out_path))
            with open(out_path) as fp:
                data = json.load(fp)
            self.assertIn('meta', data)
        finally:
            os.unlink(out_path)

    def test_zero_duration_edge(self):
        """Single timestamp edge case handled."""
        a = PacketAnalyzer(self.valid_csv)
        a.load_data()
        a.df = a.df.iloc[:1]  # force single row
        a.analyze_throughput()
        self.assertGreater(a.results['throughput']['pps'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)