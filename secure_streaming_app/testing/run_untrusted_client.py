"""
run_untrusted_client.py

Testing the security of the identity and trust_store. 
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handshake.identity import Identity
from streaming.stream_client import start_client


def main():
    #Load client identity
    identity = Identity(
        "fake_client", #Only changing the identity.
        "storage/rsa_keys/client_private.pem",
        "storage/rsa_keys/client_public.pem",
        "storage/trust_store.json"
    )
    #SERVER_IP is hardcoded and will need to be changed depending on where run_server.py is run. 
    #For local testing, 127.0.0.1
    #For testing with VM, 192.168.1.3 if server is run on my local machine. 
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 5050

    print(f"[UNTRUSTED CLIENT] connecting to server at {SERVER_IP}: {SERVER_PORT}")
    try:
        start_client(SERVER_IP, SERVER_PORT, identity)
    except Exception as e:
        print(f"[UNTRUSTED CLIENT] Connection rejected as expected: {e}")

if __name__ == "__main__":
    main()
