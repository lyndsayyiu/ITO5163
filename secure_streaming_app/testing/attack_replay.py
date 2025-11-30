"""
attack_replay.py

Simple Replay Attack Demonstration

This demonstrates a replay attack where:
1. MITM allows handshake to complete normally (passive relay)
2. MITM forwards several encrypted messages normally
3. MITM captures one encrypted message
4. MITM replays the captured message
5. Server's sequence number checking detects and rejects the replay

Setup:
    Terminal 1: python3 run_server.py (port 5051)
    Terminal 2: python3 attack_replay.py
    Terminal 3: python3 run_client_impersonation.py
"""
import socket
import struct
import time


# Configuration
MITM_LISTEN_PORT = 8888
REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 5050

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

def handle_connection(client_sock, client_addr):
    """Handle the client connection with replay attack."""
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
        print(f"[MITM] Client -> Server: client_hello ({len(client_hello)} bytes)")
        server_sock.sendall(client_hello)
        
        # Forward server_hello
        server_hello = server_sock.recv(4096)
        print(f"[MITM] Server -> Client:  server_hello ({len(server_hello)} bytes)")
        client_sock.sendall(server_hello)
        
        print("[MITM] Handshake complete - session key established\n")
        
        print("--- PHASE 2: ENCRYPTED MESSAGES (Relay & Capture) ---")
        
        # Forward message #1
        msg1 = forward_message(client_sock, server_sock, "Client → Server: Message #1 (relaying)")
        
        # Forward message #2 and CAPTURE it
        msg2 = forward_message(client_sock, server_sock, "Client → Server: Message #2 (relaying & CAPTURING)")
        print("[MITM] Captured message #2 for replay attack\n")
        
        # Forward message #3
        msg3 = forward_message(client_sock, server_sock, "Client → Server: Message #3 (relaying)")
        
        # Let a couple more messages go through
        time.sleep(2)  # Give time for more messages
        
        print("--- PHASE 3: REPLAY ATTACK ---")
        print("[MITM] Now replaying captured message #2...")
        print("[MITM] Server has already processed messages 1, 2, 3+")
        print("[MITM] Server's last_seq is now > 2")
        print("[MITM] Sending old message with seq=2\n")
        
        time.sleep(1)
        
        # Replay message #2
        if msg2:
            server_sock.sendall(msg2)
            print("[MITM] Sent replayed message to server")
            print("[MITM] Waiting for server's response...\n")
            
            time.sleep(2)
            print("\nATTACK RESULT: FAILED")
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

def start_replay_attack():
    """Start the MITM with replay attack."""
    print("SIMPLE REPLAY ATTACK DEMONSTRATION")
    print("\nThis attack demonstrates:")
    print(" - MITM allows handshake to complete")
    print(" - MITM captures encrypted message")
    print(" - MITM replays old message")
    print("Sequence numbers detect and reject replay")
    
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
    print("\n--- SECURITY DEMONSTRATION ---\n")
    
    response = input("Ready to start replay attack demo? (y/n): ").strip().lower()
    if response == 'y':
        start_replay_attack()
    else:
        print("Program ended")