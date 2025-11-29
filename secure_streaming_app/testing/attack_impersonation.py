"""
attack_impersonation.py

Impersonation Attack Demonstration

This script acts as an impersonation attack where an attacker tricks the real client
1. Intercepts the REAL client_hello from the legitimate client
2. Replaces the client's ECDH public key with the attacker's key
3. Forwards the modified message to the server
4. Server detects the invalid signature and REJECTS

This demonstrates a realistic attack scenario where the attacker is positioned
between client and server, capturing and modifying actual network traffic.

Usage:
    Terminal 1: python3 run_server.py
    Terminal 2: python3 attack_mitm_realistic.py  (this becomes the proxy)
    Terminal 3: python3 run_client.py --target 127.0.0.1:8888  (client connects to attacker)
    
Note: You'll need to modify run_client.py to connect to port 8888 instead of 5050,
      or pass server address as argument.
"""
import socket
import json
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from handshake.ecdh import ECDHKeyPair
from streaming.protocol import parse_client_hello, build_client_hello, b64_encode, b64_decode

# Attacker's proxy configuration
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888

# Real server configuration  
REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 5050

def handle_client_connection(client_sock, client_addr):
    """
    Handle connection from the client (victim).
    Intercepts client_hello, modifies it, and forwards to real server.
    """
    print(f"\n[ATTACKER] Client connected from {client_addr}")
    print("[ATTACKER] Waiting to intercept client_hello...\n")
    
    try:
        # === STEP 1: Receive the legitimate client_hello ===
        client_hello_data = client_sock.recv(4096)
        
        if not client_hello_data:
            print("[ATTACKER] No data received from client")
            return
            
        client_hello_str = client_hello_data.decode("utf-8")
        print("[ATTACKER] INTERCEPTED legitimate client_hello!")
        
        try:
            client_hello_json = json.loads(client_hello_str)
            print(f"\nOriginal message from legitimate client:")
            print(f" - Type: {client_hello_json.get('type')}")
            print(f" - Device ID: {client_hello_json.get('device_id')}")
            print(f" - ECDH Public Key: {client_hello_json.get('ecdh_public_key')[:30]}...")
            print(f" - RSA Signature: {client_hello_json.get('signature')[:30]}...")
        except:
            print("[ATTACKER] ERROR: Could not parse as JSON - invalid client_hello")
            return
        
        # === STEP 2: Parse the legitimate client_hello ===
        try:
            device_id, legit_ecdh_pubkey, legit_signature = parse_client_hello(client_hello_str)
            print(f"[ATTACKER] Parsed legitimate client_hello:")
            print(f" - Device ID: {device_id}")
            print(f" - ECDH key: {len(legit_ecdh_pubkey)} bytes")
            print(f" - Signature: {len(legit_signature)} bytes")
        except Exception as e:
            print(f"[ATTACKER] Failed to parse client_hello: {e}")
            return
        
        # === STEP 3: Generate attacker's malicious ECDH key pair ===
        print(f"\n[ATTACKER] Generating MALICIOUS ECDH key pair...")
        attacker_ecdh = ECDHKeyPair()
        attacker_ecdh_pubkey = attacker_ecdh.public_bytes()
        print(f"[ATTACKER] Generated attacker's ECDH key ({len(attacker_ecdh_pubkey)} bytes)")
        
        # === STEP 4: Create MODIFIED client_hello with attacker's key ===
        print(f"[ATTACKER] Creating MALICIOUS client_hello...")
        print(f" - Keeping device_id: {device_id}")
        print(f" - REPLACING legitimate ECDH key with attacker's key")
        print(f" - Keeping original signature (can't forge new one!)")
        
        malicious_client_hello = build_client_hello(
            device_id,
            attacker_ecdh_pubkey,  # ← ATTACKER'S KEY (malicious)
            legit_signature         # ← Original signature (attacker can't forge)
        )
        
        print(f"\n[ATTACKER] Modified message being sent to server:")
        malicious_json = json.loads(malicious_client_hello)
        print(f" - Device ID: {malicious_json.get('device_id')}")
        print(f" - ECDH Key: {malicious_json.get('ecdh_public_key')[:30]}... (ATTACKER'S)")
        print(f" - Signature: {malicious_json.get('signature')[:30]}... (ORIGINAL)")
        
        # === STEP 5: Forward modified message to real server ===
        print(f"\n[ATTACKER] Forwarding MALICIOUS client_hello to real server...")
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))
        print(f" - Connected to real server at {REAL_SERVER_HOST}:{REAL_SERVER_PORT}")
        
        server_sock.sendall(malicious_client_hello.encode("utf-8"))
        print(f" - Sent malicious client_hello to server")
        
        # === STEP 6: Wait for server response ===
        print(f"\n[ATTACKER] Waiting for server response...")
        print(f" - (Server will verify signature...)")
        
        server_sock.settimeout(5.0)
        try:
            response = server_sock.recv(4096)
            if response:
                print(f"\n[ATTACKER] Unexpected! Server sent response:")
                print(f" - {response[:100]}")
                print(f" - (This shouldn't happen - signature should have failed)")
            else:
                print(f"\n[ATTACKER] Server closed connection (no response)")
        except socket.timeout:
            print(f"\n[ATTACKER] No response from server (connection likely rejected)")
        
        server_sock.close()
        
    except Exception as e:
        print(f"\n[ATTACKER] Error during attack: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        client_sock.close()
        print(f"\n[ATTACKER] Closed connection to client")

def start_mitm_proxy():
    """
    Start the MITM proxy server that sits between client and real server.
    """
    print("=" * 70)
    print("REALISTIC IMPERSONATION ATTACK DEMONSTRATION")
    print("=" * 70)
    print("\n[ATTACKER] Starting MITM proxy server...")
    print(f"[ATTACKER] Proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    print(f"[ATTACKER] Will forward to real server at {REAL_SERVER_HOST}:{REAL_SERVER_PORT}")
    print()
    print("\nWaiting for client to connect to proxy...\n")
    
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind((PROXY_HOST, PROXY_PORT))
    proxy_sock.listen(5)
    
    try:
        while True:
            client_sock, client_addr = proxy_sock.accept()
            # Handle each client in the main thread for clearer demonstration
            handle_client_connection(client_sock, client_addr)
            break  # Exit after handling one connection for demo
            
    except KeyboardInterrupt:
        print("\n\n[ATTACKER] MITM proxy stopped by user")
    finally:
        proxy_sock.close()

if __name__ == "__main__":
    print("\n--- IMPERSONATION ATTACK DEMONSTRATION -")
    print("This demonstrates an impersonation attack.")
    print("\nPrerequisites:")
    print("1. Real server must be running: python3 run_server.py")
    print("2. Modify run_client.py to connect to port 8888 instead of 5050")
    print("   (Or a modified version for testing: run_client_impersonation.py)")
    print("")
    
    response = input("Ready to start MITM proxy? (y/n): ").strip().lower()
    if response == 'y':
        start_mitm_proxy()
    else:
        print("Setup instructions:")
        print("1. Start real server: python3 run_server.py")
        print("2. Start this MITM proxy: python3 attack_mitm_realistic.py")
        print("3. Modify client to connect to 127.0.0.1:8888")
        print("4. Run client: python3 run_client.py")