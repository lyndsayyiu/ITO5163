"""
attack_injection.py

Simple Message Injection Attack Demonstration

This demonstrates a message injection attack where:
1. MITM allows handshake to complete normally (passive relay)
2. MITM forwards several encrypted messages normally
3. MITM blocks one message from the client
4. MITM tries to inject a fake encrypted message
5. Server's AES-GCM authentication detects invalid tag and rejects


Setup:
    Terminal 1: python3 run_server.py (port 5050 - no modification needed)
    Terminal 2: python3 attack_injection.py (attacker on port 8888)
    Terminal 3: python3 run_client_impersonation.py (connects to port 8888)
"""
import socket
import struct
import json
import base64
import time
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configuration
MITM_LISTEN_PORT = 8888      # Client connects here (attacker's proxy)
REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 5050      # Real server

def recv_exact(sock, length):
    """Receive exactly length bytes."""
    chunks = []
    bytes_read = 0
    while bytes_read < length:
        chunk = sock.recv(length - bytes_read)
        if not chunk:
            return None
        chunks.append(chunk)
        bytes_read += len(chunk)
    return b"".join(chunks)

def forward_message(src_sock, dst_sock, description):
    """Receive a length-prefixed message and forward it."""
    # Receive length prefix (4 bytes)
    length_prefix = recv_exact(src_sock, 4)
    if not length_prefix:
        return None
    
    msg_length = struct.unpack("!I", length_prefix)[0]
    
    # Receive the message
    message_data = recv_exact(src_sock, msg_length)
    if not message_data:
        return None
    
    full_message = length_prefix + message_data
    
    print(f"[MITM] {description} ({len(full_message)} bytes)")
    
    # Forward it
    dst_sock.sendall(full_message)
    
    return full_message

def create_fake_encrypted_message(seq):
    """
    Create a fake encrypted message.
    
    Since MITM doesn't have session key, this has random data
    that will fail AES-GCM authentication.
    """
    # Random data (we don't have the session key)
    fake_nonce = os.urandom(12)
    fake_ciphertext = os.urandom(32)
    fake_tag = os.urandom(16)
    
    # Build message structure
    fake_message = {
        "type": "data",
        "seq": seq,
        "nonce": base64.b64encode(fake_nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(fake_ciphertext).decode('utf-8'),
        "tag": base64.b64encode(fake_tag).decode('utf-8')
    }
    
    # Serialize to JSON
    message_json = json.dumps(fake_message)
    message_bytes = message_json.encode('utf-8')
    
    # Add length prefix
    length_prefix = struct.pack("!I", len(message_bytes))
    
    return length_prefix + message_bytes

def handle_connection(client_sock, client_addr):
    """Handle the client connection with injection attack."""
    print(f"\n[ATTACKER] Client connected from {client_addr}")
    
    try:
        # Connect to real server
        print(f"[ATTACKER] Connecting to real server at {REAL_SERVER_HOST}:{REAL_SERVER_PORT}")
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))
        print(f"[ATTACKER] Connected to real server\n")
        print("--- PHASE 1: HANDSHAKE (Passive Relay) ---")
    
        
        # Forward client_hello (not length-prefixed, just JSON)
        client_hello = client_sock.recv(4096)
        print(f"[MITM] Client -> Server client_hello ({len(client_hello)} bytes)")
        server_sock.sendall(client_hello)
        
        # Forward server_hello
        server_hello = server_sock.recv(4096)
        print(f"[MITM] Server -> Client server_hello ({len(server_hello)} bytes)")
        client_sock.sendall(server_hello)
        
        print("[MITM] Handshake complete - session key established\n")
        print(" --- PHASE 2: ENCRYPTED MESSAGES (Relaying) ---")
        # Forward message #1
        forward_message(client_sock, server_sock, "Client -> Server Message #1 (relaying)")
        
        # Forward message #2
        forward_message(client_sock, server_sock, "Client -> Server Message #2 (relaying)")
        
        # Forward message #3
        forward_message(client_sock, server_sock, "Client -> Server Message #3 (relaying)")
        
        # Block message #4
        print("\n[MITM] Receiving message #4...")
        length_prefix = recv_exact(client_sock, 4)
        msg_length = struct.unpack("!I", length_prefix)[0]
        blocked_msg = recv_exact(client_sock, msg_length)
        
        print(f"[MITM] BLOCKED message #4 ({msg_length} bytes)")
        print("[MITM] Client's real message #4 will not reach server\n")
        
        time.sleep(1)
        
        print(" --- PHASE 3: MESSAGE INJECTION ATTACK ---")
        print("[MITM] Creating fake encrypted message to replace #4...")
        print("\nFake message details:")
        print(" - Sequence number: 4 (correct)")
        print(" - Structure: Valid JSON")
        print(" - Nonce: Random 12 bytes")
        print(" - Ciphertext: Random 32 bytes")
        print(" - Tag: Random 16 bytes (NOT valid!)")
        print("\n[MITM] Problem: MITM doesn't have session key")
        print(" X Can't compute valid AES-GCM tag")
        print(" X Tag requires: session_key + ciphertext (via Galois Hash)")
        print(" X Our tag is just: random bytes")
        
        # Create fake message
        fake_msg = create_fake_encrypted_message(seq=4)
        
        print(f"\n[MITM] Sending fake message to server...")
        time.sleep(1)
        
        server_sock.sendall(fake_msg)
        print("[MITM] ✓ Fake message sent")
        print("[MITM] Server will attempt AES-GCM decryption...\n")
        
        time.sleep(2)
        time.sleep(2)
        
    except Exception as e:
        print(f"\n[ATTACKER] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            server_sock.close()
        except:
            pass
        client_sock.close()
        print(f"\n[ATTACKER] Connection closed")

def start_inject_attack():
    """Start the MITM with injection attack."""
    print("\nThis attack demonstrates:")
    print(" - MITM allows handshake to complete")
    print(" - MITM blocks legitimate message")
    print(" - MITM injects fake encrypted message")
    print(" - AES-GCM authentication detects and rejects")
    
    print(f"\n[MITM] Starting on port {MITM_LISTEN_PORT}")
    print(f"[MITM] Forwarding to {REAL_SERVER_HOST}:{REAL_SERVER_PORT}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", MITM_LISTEN_PORT))
    sock.listen(1)
    
    print(f"[MITM] Waiting for client...\n")
    
    try:
        client_sock, client_addr = sock.accept()
        handle_connection(client_sock, client_addr)
    except KeyboardInterrupt:
        print("\n\n[MITM] Stopped by user")
    finally:
        sock.close()

if __name__ == "__main__":
    print("\n --- SECURITY DEMONSTRATION ---\n")
    
    response = input("Ready to start injection attack demo? (y/n): ").strip().lower()
    if response == 'y':
        start_inject_attack()
    else:
        print("\nSetup server on port 5051 first.")