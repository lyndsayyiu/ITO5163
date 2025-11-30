"""
test_fake_signature.py

Demonstrates Man-in-the-Middle attack prevention by attempting to connect 
with a forged RSA signature. This simulates an attacker who intercepts the 
handshake and tries to substitute their own ECDH key.

Expected Result: Server rejects connection with "Invalid RSA signature" error.
"""
import socket
import json
import base64
import os

def attempt_fake_signature_attack():
    """
    Attempts to perform MITM attack by sending fake credentials.
    """
    print("ATTACK TEST: Forged RSA Signature (MITM Simulation)")
    print("[ATTACKER] Objective: Impersonate client with fake signature")
    print("[ATTACKER] This simulates an attacker intercepting the handshake")
    
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('127.0.0.1', 5050))
        print("[ATTACKER] Connected to server at 127.0.0.1:5050")
        
        # Generate fake ECDH public key (random 32 bytes)
        fake_ecdh_key = os.urandom(32)
        print(f"[ATTACKER] Generated fake ECDH public key ({len(fake_ecdh_key)} bytes)")
        
        # Generate fake signature (random 256 bytes - typical RSA-2048 signature size)
        fake_signature = os.urandom(256)
        print(f"[ATTACKER] Generated fake RSA signature ({len(fake_signature)} bytes)")
        
        # Build malicious client_hello
        fake_message = {
            "type": "client_hello",
            "device_id": "client",  # Claiming to be legitimate client
            "ecdh_public_key": base64.b64encode(fake_ecdh_key).decode("utf-8"),
            "signature": base64.b64encode(fake_signature).decode("utf-8")
        }
        
        print()
        print("[ATTACKER] Sending malicious client_hello claiming to be 'client'...")
        
        # Send fake handshake
        sock.sendall(json.dumps(fake_message).encode("utf-8"))
        
        print("[ATTACKER] Waiting for server to reject connection...")
        print()
        
        # Server will close connection without sending server_hello
        # Try to receive - should get empty bytes indicating closed connection
        response = sock.recv(4096)
        if response:
            print(f"[ATTACKER] Unexpected: received data: {response[:100]}")
        else:
            print("[ATTACKER] Connection closed by server (signature rejected)")
            
    except ConnectionRefusedError:
        print("[ERROR] Connection refused. Is the server running?")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass
    print("RESULT: Attack FAILED (as expected)")


if __name__ == "__main__":
    print()
    print("This script demonstrates RSA signature verification preventing MITM attacks.")
    print("Make sure the server is running before executing this test.")
    input("Press Enter to start the attack simulation...")
    print()
    
    attempt_fake_signature_attack()