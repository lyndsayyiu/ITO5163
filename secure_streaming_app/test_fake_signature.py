"""
test_fake_signature.py

Demonstrates Main-in-the-Middle attack prevention by attempting to make a connection with a forged RSA signature. 
This simulates an attacker who intercepts the handshake and tries to subtitute their own ECDH key. 

Expected result: Server rejects connection with "Invalid RSA signature" error.
"""
import socket
import json
import base64
import os

def attempt_fake_signature_attack():
    """
    Attempts to perform a MITM attack by sending fake credentials.
    """
    print("ATTACK TEST: Forged RSA Signature (MITM Attack Simulation)")
    
    try:
        #Connect to server
        SERVER_IP = '127.0.0.1'
        SERVER_PORT = 5050
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[ATTACKER] Connected to server at 127.0.0.")

        #Generate a fake ECDH public key (random 32 bytes)
        fake_ecdh_key = os.urandom(32)
        print(f"[ATTACKER] Generate fake ECDH public key ({len(fake_ecdh_key)} bytes)")

        #Generate fake signature (random 256 bytes to match RSA-2048 signature size)
        fake_signature = os.urandom(256)

        #Build fake client_hello
        fake_message = {
            "type": "client_hello",
            "device_id": "client", #claiming to be the legitimate client
            "ecdh_public_key": base64.b64encode(fake_ecdh_key).decode("utf-8"),
            "signature": base64.b64encode(fake_signature).decode("utf-8")
        }

        print()
        print("[ATTACKER] Sending malicious client_hello claiming to be 'client'...")

        #Send fake handshake
        sock.sendall(json.dumps(fake_message).encode("utf-8"))

        print("[ATTACKER] Waiting for server response...")
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

if __name__ == "__main__":
    attempt_fake_signature_attack()
        