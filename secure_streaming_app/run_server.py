"""
run_server.py

Entry point for launching the secure streaming server.

The server:
    1. Loads it's RSA identity (private + public key)
    2. Loads trusted RSA public keys from trust_store.json
    3. Starts the TCP server on 0.0.0.0:5050 and waits for communications
    4. Waits for a client_hello
    5. Verifies client_hello and performs key derivation is valid. Otherwise, closes connection.
    4. Sends back server_hello
    5. Receives and decrypts messages. Otherwise, closes connection if messages are not valid (corrupted/tampered/etc.)
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
    SERVER_PORT = 5050

    print(f"[SERVER] Starting on {SERVER_IP}: {SERVER_PORT}")
    start_server(SERVER_IP, SERVER_PORT, identity)

if __name__ == "__main__":
    main()