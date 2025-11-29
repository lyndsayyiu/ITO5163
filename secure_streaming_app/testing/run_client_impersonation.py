"""
run_client_impersonation_test.py

modified run_client.py file for testing a MITM attack. 
This client connects to the ATTACKER's proxy (port 8888) instead of the real server. 
No modified behaviour of the client. 

Usage:
    Terminal 1: python3 run_server.py (real server on port 5050)
    Terminal 2: python3 attack_mitm_realistic.py (attacker proxy on port 8888)
    Terminal 3: python3 run_client_mitm_test.py (victim client connecting to port 8888)

Requirements:
 - Must run from root python3 testing/run_client_impersonation.py
"""
from handshake.identity import Identity
from streaming.stream_client import start_client

def main():
    print("--------- MITM ")
    #Load client identity
    identity = Identity(
        "client",
        "storage/rsa_keys/client_private.pem",
        "storage/rsa_keys/client_public.pem",
        "storage/trust_store.json"
    )
    #SERVER_IP is hardcoded and will need to be changed depending on where run_server.py is run. 
    #For local testing, 127.0.0.1
    #For testing with VM, 192.168.1.3 if server is run on my local machine. 
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 8888 #Changed to the attacker's port
    print(f"[CLIENT] connecting to server at {SERVER_IP}: {SERVER_PORT}")
    start_client(SERVER_IP, SERVER_PORT, identity)

if __name__ == "__main__":
    main()