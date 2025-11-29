"""
FULL ATTACK DEMO: Replays old client_hello + old ciphertext

This script demonstrates:
  - Extracting old handshake messages from PCAP
  - Attacker attempting to reuse old client_hello
  - Server generating a fresh ephemeral ECDH key
  - Replay of encrypted messages failing (MAC mismatch)
"""

import socket
import sys
import json
from scapy.all import rdpcap, TCP


############################################################
#       1. Extract and Reassemble TCP Streams
############################################################

def reassemble_streams(pcap_file):
    packets = rdpcap(pcap_file)
    streams = {}

    for pkt in packets:
        if TCP not in pkt:
            continue

        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            continue

        key = (pkt[1].src, tcp.sport, pkt[1].dst, tcp.dport)
        if key not in streams:
            streams[key] = b""
        streams[key] += payload

    return streams


############################################################
#       2. Extract JSON messages (client_hello + data)
############################################################

def extract_messages(raw_bytes):
    client_hello = None
    data_msgs = []

    i = 0
    while i < len(raw_bytes):
        if i + 4 > len(raw_bytes):
            break

        length = int.from_bytes(raw_bytes[i:i+4], "big")
        msg_start = i + 4
        msg_end = msg_start + length

        if msg_end > len(raw_bytes):
            break

        frame = raw_bytes[msg_start:msg_end]

        try:
            text = frame.decode("utf-8", errors="ignore")
            j = json.loads(text)
        except:
            i = msg_end
            continue

        if j.get("type") == "client_hello" and client_hello is None:
            client_hello = raw_bytes[i:msg_end]

        if j.get("type") == "data":
            data_msgs.append((j["seq"], raw_bytes[i:msg_end]))

        i = msg_end

    return client_hello, data_msgs


############################################################
#       3. Perform the fake attack
############################################################

def perform_attack(client_hello, encrypted_msgs):
    print("\n=== STARTING ATTACK ===\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    sock.connect(("127.0.0.1", 5050))
    print("[+] Connected to server.\n")

    ##################################################
    # Step 1: Replay old client_hello from PCAP
    ##################################################

    print("[*] Sending OLD client_hello captured previously...")
    sock.sendall(client_hello)

    try:
        resp = sock.recv(4096)
        print("[Server replied]:", resp.decode(errors="ignore"))
    except socket.timeout:
        print("[!] No server reply (likely handshake failed).")

    ##################################################
    # Step 2: Replay encrypted data messages
    ##################################################

    print("\n[*] Replaying OLD encrypted messages...")
    for seq, packet in encrypted_msgs[:3]:
        print(f"  -> sending seq={seq}")
        sock.sendall(packet)

    print("\n=== ATTACK COMPLETE ===")
    print("Expected outcome:")
    print(" - Server rejects data: wrong keys")
    print(" - AEAD authentication fails")
    print(" - Replay attack blocked by ephemeral ECDH")


############################################################
#       4. Main Entry
############################################################

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 replay_full_attack_demo.py capture.pcap")
        return

    pcap = sys.argv[1]
    print(f"\n--- Analyzing PCAP: {pcap} ---\n")

    streams = reassemble_streams(pcap)
    client_hello = None
    encrypted = []

    for key, stream in streams.items():
        ch, ds = extract_messages(stream)
        if ch:
            client_hello = ch
        encrypted.extend(ds)

    if not client_hello:
        print("❌ Could not find client_hello in pcap.")
        print("   Make sure the capture includes the start of the handshake.")
        return

    print("Found client_hello!")
    print(f"Found {len(encrypted)} encrypted messages.\n")

    input("Press Enter to launch attack...")

    perform_attack(client_hello, encrypted)


if __name__ == "__main__":
    main()
