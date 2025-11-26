"""
stream_server.py

Handles the incoming side of the secure streaming channel:
- Accepts incoming TCP client connections
- Performs the secure handshake (ECDH + RSA authenticiation)
- Derives the session key
- Receives encrypted messages over the secure channel
- Decrypts and prints the plaintext messages
"""
import socket
import json

from handshake.ecdh import ECDHKeyPair
from handshake.identity import Identity
from handshake.rsa_auth import verify_ecdh_public_key_signature, sign_ecdh_public_key
from handshake.key_derivation import derive_session_key
from streaming.protocol import parse_client_hello, build_server_hello

from crypto.secure_channel import secure_receive

def start_server(host: str, port: int, identity: Identity):
    """
    Starts the secure streaming server.

    Creates a TCP socket, accepts one client connection, performs the authenticated ECDH handshake,
    then enters a loop receiving encrypted messages via AES-GCM through the secure_receive() function. 

    Arguments:
        host (str): IP address or hostname to bind to.
        port (int): The TCP port to listen on.
        identity (Identity): Server's RSA identity + trust store. 
    """
    print(f"[SERVER] Starting server on {host}: {port}")

    #Create TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(1)
    print(f"[SERVER] Waiting for client connection...")

    conn, addr = sock.accept()
    print(f"[SERVER] Client connected from {addr}")

    #Perform handshake
    session_key = server_handshake(conn, identity)
    print(f"[SERVER] Handshake complete. Session key established.")

    last_seq = 0 #Instatiating to help prevent replay attacks
    
    #Receive encrypted messages
    while True:
        try:
            seq, message_dict = secure_receive(conn, session_key)

            #Checking for a replayed message
            if seq <= last_seq:
                print(f"[WARNING] Replay message detected! Received seq={seq}, but last_seq={last_seq}. Message rejected.")
                continue
            last_seq = seq

            print(f"[SERVER] Received (seq={seq}): {message_dict}")

        except Exception as e:
            print(f"[SERVER] Connection closed or error: {e}")
            break

#Handshake logic
def server_handshake(conn, identity: Identity) -> bytes:
    """
    Performs the secure handshake with the connecting client. 

    Receives the client_hello, extract's the device_id, ECDH public key and RSA signature and verifies signature using trust store.
    Generates the server's ephemeral ECDH key and computes shared secret. Session key is then derived.
    Send's back server_hello with RSA signature. 

    Arguments:
        conn (socket.socket): The TCP connection of the client
        identity (Identity): The server's RSA identity.         

    Returns:
        bytes: The final symmetric session key. 
    """
    # --- Receive client_hello ---
    raw_data = conn.recv(4096) #Read handshake message
    if not raw_data:
        raise ConnectionError("[SERVER] Failed to receive client_hello")
    
    try:
        client_hello_json = raw_data.decode("utf-8")
        client_hello = json.loads(client_hello_json)
    except Exception as e:
        raise ValueError(f"[SERVER] Invalid client_hello format: {e}")
    
    print(f"[SERVER] Received client_hello: {client_hello}")

    # --- Parse information from client_hello ---
    try:
        client_device_id, client_pubkey_bytes, client_signature = parse_client_hello(client_hello)
    except Exception as e:
        raise ValueError(f"[SERVER] Failed to parse client_hello")
    
    print(f"[SERVER] Client device_id: {client_device_id}")
    print(f"[SERVER] Client ECDH public key ({len(client_pubkey_bytes)} bytes)")

    # --- Verifying Client's RSA signature ---

    #Retrieving the client's trusted RSA Public key from the trust store. 
    try:
        client_rsa_public_key = identity.get_peer_public_key(client_device_id)
    except Exception as e: 
        raise ValueError(f"[SERVER] Unknown or untrusted client '{client_device_id}': {e}")
    
    #Verifying the RSA signature on the client's ECDH public key. 
    is_valid = verify_ecdh_public_key_signature(
        client_rsa_public_key,
        client_pubkey_bytes,
        client_signature
    )

    if not is_valid:
        raise ValueError("[SERVER] Invalid RSA signature on client's ECDH public key.")
    
    print("[SERVER] Client authentification successful via RSA signature.")

    # --- Generate server's ECDH key pair
    server_ecdh = ECDHKeyPair()
    server_pubkey_bytes = server_ecdh.public_bytes()

    print(f"[SERVER] Generated server ECDH key pair ({len(server_pubkey_bytes)} bytes)")

    # --- Compute shared secret ---
    shared_secret = server_ecdh.compute_shared_secret(client_pubkey_bytes)
    print(f"[SERVER] Shared secret computed ({len(shared_secret)} bytes)")

    # --- Key derivation ---
    session_key = derive_session_key(shared_secret)
    print(f"[SERVER] Session key derived ({len(session_key)} bytes)")

    # --- Build server_hello ---
    #Sign the ECDH public key bytes with the server's RSA private key
    server_signature = sign_ecdh_public_key(identity.private_key, server_pubkey_bytes)

    #Build server_hello message
    server_hello = build_server_hello(identity.device_id, server_pubkey_bytes, server_signature)

    server_hello_json = json.dumps(server_hello).encode("utf-8")
    conn.sendall(server_hello_json)
    print(f"[SERVER] Sent server_hello to client.")

    #Handshake complete: return the derived session key
    return session_key


