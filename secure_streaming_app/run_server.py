"""
run_server.py

Entry point for launching the secure streaming server.

The server performs:
    1. Loading it's RSA identity (private + public key)
    2. Loading trust RSA public keys from trust_store.json
    3. Starting the TCP server on 0.0.0.0 for VM compatability
    4. Performing the authenticated ECDH handshake
    5. Receiving and decrypting secure streaming messages
"""
from handshake.identity import Identity
from streaming.stream_server import start_server

def main():
    #Load server identity
    identity = Identity(
        "server",
        "storage/rsa_keys/server_private.pem",
        "storage/rsa_keys/server_public.pem",
        "storage/trust_store.json"
    )

    # Bind to all interfaces
    SERVER_IP = "0.0.0.0"
    SERVER_PORT = 5000

    print(f"[SERVER] Starting on {SERVER_IP}: {SERVER_PORT}")
    start_server(SERVER_IP, SERVER_PORT, identity)

if __name__ == "__main__":
    main()