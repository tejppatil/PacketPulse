#!/bin/bash
# PacketPulse — Simulate malicious URL visits for testing urlscan
# Run this while packetpulse urlscan --live is running

echo "[*] Simulating visits to suspicious/malicious URLs..."

# These are safe-to-request domains used for testing only
# The URL scanner will flag them based on structure analysis

echo "[1] Triggering DNS queries for high-entropy domains (DGA simulation)..."
host xk3mf9qz2vwl.top 2>/dev/null
host a1b2c3d4e5f6.xyz 2>/dev/null
host zxqwerty12345.tk 2>/dev/null

echo "[2] Curl to suspicious-structured URLs..."
curl -s --max-time 3 "http://free-prize-winner.top/claim?id=123&token=abc" -o /dev/null 2>/dev/null
curl -s --max-time 3 "http://secure-login-verify.xyz/update" -o /dev/null 2>/dev/null
curl -s --max-time 3 "http://192.168.1.1/admin" -o /dev/null 2>/dev/null

echo "[3] Simulating plaintext credential POST..."
curl -s --max-time 3 -X POST "http://test.local/login" \
  -d "username=admin&password=password123" -o /dev/null 2>/dev/null

echo "[*] Done. Check packetpulse output for flagged URLs."
