"""
test_tampering.py

Simple tampering demonstration: flip one bit in encrypted message.

This demonstrates that AES-GCM provides message integrity protection.
Any modification to the ciphertext will cause authentication to fail.

Usage:
    1. Start server: python run_server.py
    2. Run this test: python test_tampering.py
"""
import socket
import json
import sys
import struct
import os

# Add parent directory to path so we can import project modules
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from handshake.ecdh import ECDHKeyPair
from handshake.identity import Identity
from handshake.rsa_auth import sign_ecdh_public_key, verify_ecdh_public_key_signature
from handshake.key_derivation import derive_session_key
from streaming.protocol import build_client_hello, parse_server_hello, build_encrypted_data_message
from crypto.aes_gcm import encrypt_message

def main():
    print("--- TAMPERING TEST ---")
    print("\nDemonstrates: AES-GCM detects even a single bit change")
    print("Attack: Flip one bit in the encrypted ciphertext")
    print("Expected: Server rejects message due to authentication failure\n")
    
    # Load client identity
    identity = Identity(
        "client",
        "storage/rsa_keys/client_private.pem",
        "storage/rsa_keys/client_public.pem",
        "storage/trust_store.json"
    )
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect(("127.0.0.1", 5050))
        print("[1] Connected to server")
        
        # Perform handshake
        print("[2] Performing handshake...")
        client_ecdh = ECDHKeyPair()
        client_pubkey_bytes = client_ecdh.public_bytes()
        signature = sign_ecdh_public_key(identity.private_key, client_pubkey_bytes)
        
        client_hello = build_client_hello(identity.device_id, client_pubkey_bytes, signature)
        sock.sendall(client_hello.encode("utf-8"))
        
        raw_data = sock.recv(4096)
        server_hello_json = raw_data.decode("utf-8")
        server_device_id, server_pubkey_bytes, server_signature = parse_server_hello(server_hello_json)
        
        server_rsa_key = identity.get_peer_public_key(server_device_id)
        is_valid = verify_ecdh_public_key_signature(server_rsa_key, server_pubkey_bytes, server_signature)
        
        if not is_valid:
            print("Server signature verification failed!")
            return
        
        shared_secret = client_ecdh.compute_shared_secret(server_pubkey_bytes)
        session_key = derive_session_key(shared_secret)
        print("Handshake complete, session key established\n")
        
        # Create encrypted message
        plaintext = {"message": "Legitimate Event"}
        plaintext_bytes = json.dumps(plaintext).encode("utf-8")
        nonce_bytes, ciphertext_bytes, tag_bytes = encrypt_message(session_key, plaintext_bytes)
        
        print("[3] Created encrypted message:")
        print(f" - Plaintext: {plaintext}")
        print(f" - Ciphertext: {ciphertext_bytes.hex()}")
        print(f" - Tag: {tag_bytes.hex()}\n")
        
        # TAMPER: Flip one bit in the ciphertext
        tampered_ciphertext = bytearray(ciphertext_bytes)
        original_byte = tampered_ciphertext[0]
        tampered_ciphertext[0] ^= 0x01  # Flip the least significant bit
        tampered_byte = tampered_ciphertext[0]
        tampered_ciphertext = bytes(tampered_ciphertext)
        
        print("[4] ATTACK: Flipping one bit in ciphertext")
        print(f" - Original byte:  0x{original_byte:02x} (binary: {bin(original_byte)})")
        print(f" - Tampered byte:  0x{tampered_byte:02x} (binary: {bin(tampered_byte)})")
        print(f" - Tampered text:  {tampered_ciphertext.hex()}\n")
        
        # Send tampered message to server
        message_json = build_encrypted_data_message(1, nonce_bytes, tampered_ciphertext, tag_bytes)
        sock.sendall(struct.pack("!I", len(message_json)) + message_json.encode("utf-8"))
        
        print("[5] Sent tampered message to server\n")
        print("RESULT:")
        print("="*70)
        print("Server should reject this message")
        print("Check server terminal for error message:")
        print("\nThis proves AES-GCM provides message integrity protection!")
        
    except ConnectionRefusedError:
        print("Could not connect to server. Is it running?")
        print("Start server with: python run_server.py")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()