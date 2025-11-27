"""
replay_from_pcap_v2.py

Extracts encrypted messages from pcap and attempts replay.

Usage: python replay_from_pcap_v2.py capture.pcap
Install: pip install scapy
"""

import socket
import sys
import json

def extract_with_scapy(pcap_file):
    """Extract TCP payloads from pcap."""
    try:
        from scapy.all import rdpcap, TCP
    except ImportError:
        print("Error: scapy not installed. Run: pip install scapy")
        return None
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return None
    
    messages = []
    for pkt in packets:
        if TCP in pkt:
            tcp = pkt[TCP]
            if tcp.dport == 5050 or tcp.sport == 5050:
                payload = bytes(tcp.payload)
                if len(payload) > 4:
                    messages.append({
                        'payload': payload,
                        'direction': 'to_server' if tcp.dport == 5050 else 'to_client'
                    })
    return messages

def get_seq_number(payload):
    """Extract sequence number from encrypted message."""
    try:
        json_data = payload[4:].decode('utf-8', errors='ignore')
        if '"type":"data"' in json_data or '"type": "data"' in json_data:
            data = json.loads(json_data)
            return data.get('seq')
    except:
        pass
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python replay_from_pcap_v2.py <capture.pcap>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    print(f"\n--- Analyzing {pcap_file} ---\n")
    
    messages = extract_with_scapy(pcap_file)
    if not messages:
        print("No messages found. Make sure you captured traffic on port 5050.")
        return
    
    print(f"Found {len(messages)} packets")
    
    # Extract data messages going to server
    data_messages = []
    for msg in messages:
        if msg['direction'] == 'to_server':
            seq = get_seq_number(msg['payload'])
            if seq:
                data_messages.append((seq, msg['payload']))
                print(f"  seq={seq} ({len(msg['payload'])} bytes)")
    
    if not data_messages:
        print("No encrypted data messages found.")
        return
    
    print(f"\nCaptured {len(data_messages)} encrypted messages")
    print("Attacker can replay these bytes but can't decrypt them (no session key)")
    
    # Attempt replay
    print("\n--- Attempting Replay ---\n")
    print("Note: This will fail (no handshake).")
    input("Press Enter to replay captured bytes...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        print("Connected to server")
        
        # Replay first 3 messages
        for i, (seq, payload) in enumerate(data_messages[:3], 1):
            print(f"Replaying seq={seq}... ", end='')
            try:
                sock.sendall(payload)
                print("sent")
            except Exception as e:
                print(f"failed: {e}")
                break
        
        sock.close()
        
    except Exception as e:
        print(f"Connection error: {e}")
    
    print("\nServer rejected (expected - no handshake performed)")
    print("Check server console for rejection message.\n")

if __name__ == "__main__":
    main()