import socket
import binascii

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5050

# Paste your Wireshark hex-stream here
REPLAY_HEX = """

""".replace("\n", "").strip()

def replay_attack():
    print("[ATTACK] Connecting to server for replay attack...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))

    print("[ATTACK] Converting hex to bytes...")
    raw_packet = binascii.unhexlify(REPLAY_HEX)

    print(f"[ATTACK] Sending {len(raw_packet)} bytes of captured ciphertext...")
    sock.sendall(raw_packet)

    print("[ATTACK] Packet sent. If server is secure, it should reject this as replay/out-of-handshake.")
    sock.close()

if __name__ == "__main__":
    replay_attack()
