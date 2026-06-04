# Packet Analysis Report

Deep analysis of nginx packet capture (`fcap.csv`).

## Environment
- Python 3.10+ with pandas/numpy
- Virtualenv: `venv/`
- Dependencies: `requirements.txt`

## Run
```bash
source venv/bin/activate
python analyze_packets.py fcap.csv
```

## Summary

### Latency
- Mean delta: 490 µs
- Median delta: 370 µs
- P99: 1.485 ms
- Burst packets (<100 µs): 12 (2.4%)

### Throughput
- 500 packets, 0.67 MB
- Capture span: 0.2 ms (sub-millisecond burst)
- Peak: 22 Gbps instantaneous
- 2.06M packets/sec average

### TCP Flags
- ACK: 478 (95.6%)
- ACK/PSH: 22 (4.4%)
- No RST/FIN/SYN observed

### Connections
- 18 unique flows
- Mean flow duration: 100 µs
- Largest flow: 131 packets (172.16.4.1:4400 ↔ 172.16.4.2:59307)

### Traffic Direction
- 172.16.1.1 → 172.16.1.2: 362 KB (dominant)
- 172.16.4.1 → 172.16.4.2: 183 KB
- 172.16.3.1 → 172.16.3.2: 144 KB
- Reverse ACKs minimal (<2 KB each)

## Notes
- Capture shows single micro-burst from 3 client subnets to nginx.
- All data is pure ACK stream (no connection setup/teardown visible).
- Heavy PSH usage indicates application-level batching.
- Reverse path carries only pure ACKs.

Generated: 2026-06-04