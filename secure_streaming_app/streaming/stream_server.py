"""
stream_server.py

Handles the incoming side of the secure streaming channel:
- Accepts incoming TCP client connections
- Performs the secure handshake (ECDH + RSA authenticiation)
    - If this fails, drops client connection. 
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

    Creates a TCP socket, accepts a client connection, performs the authenticated ECDH handshake,
    then enters a loop receiving encrypted messages via AES-GCM through the secure_receive() function. 

    Arguments:
        host (str): IP address or hostname to bind to.
        port (int): The TCP port to listen on.
        identity (Identity): Server's RSA identity + trust store. 
    """
    print(f"[SERVER] Starting server on {host}: {port}")

    #Create TCP socket to accept incoming connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #Enable address reuse
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #Bind to specified host and port
    try:
        sock.bind((host, port))
    except OSError as e:
        print(f"[SERVER ERROR] Failed to bind to {host}:{port}")
        sys.exit(1)
    
    #Listen for incoming connections (queue up to 5 pending connections, arbitrary amount currently)
    sock.listen(5)

    try:
        while True:
            print(f"[SERVER] Waiting for client connection...")

            #Accept incoming connection
            try:
                conn, addr = sock.accept()
                print(f"[SERVER] Client connected from {addr}")
            except KeyboardInterrupt:
                print("\n[SERVER] Shutdown requested by user")
                break
            except Exception as e:
                print(f"[SERVER ERROR] Failed to accept connection: {e}")
                continue

            #Handle client connection
            try:
                #Perform handshake
                session_key = server_handshake(conn, identity)
                #If none, handshake has failed. 
                if session_key is None:
                    print("[SERVER] Handshake failed. Rejecting client.")
                    #Close connection, wait for next client
                    conn.close()
                    continue

                print(f"[SERVER] Handshake complete. Session key established.")

                #Initialise sequence counter to detect and prevent replay attacks.
                last_seq = 0 

                #Receive encrypted messages
                while True: 
                    try:
                        #Receive and decrypt message
                        seq, message_dict = secure_receive(conn, session_key)

                        #Checking for a replayed message
                        if seq <= last_seq:
                            print(f"[WARNING] Replay message detected! Received seq={seq}, but last_seq={last_seq}. Message rejected.")
                            continue
                        
                        #Update sequence counter if valid
                        last_seq = seq
                        print(f"[SERVER] Received (seq={seq}): {message_dict}")
                    except ValueError as e:
                        #Message decryption/validation failure
                        print(f"[SERVER] Message validation failed from {addr}: {e}")
                        print(f"[SERVER] Possible tampering/corruption/protocol violation.")
                        break
                    
                    except ConnectionError as e:
                        #Client disconnection or network issue
                        print(f"[SERVER] Connection lost: {e}")
                        break
                    
                    except Exception as e:
                        #Unexpected error during message procesing
                        print(f"[SERVER] Unexpected error receiving mesages: {e}")
                        break

                    except Exception as e:
                        print(f"[SERVER] Connection closed or error: {e}")
                        break

            #Exception handling for handshake
            except ValueError as e:
                #Validation failure during handshake
                print(f"[SERVER] Handshake validation error: {e}")
                print("[SERVER] Possible invalid signature, untrusted device or malformed message.")
            except ConnectionError as e:
                #Connection/Network issue during handshake
                print(f"[SERVER] Connection error during handshake: {e}")
            except Exception as e:
                print(f"[SERVER] Unexpected handshake error: {e}")
            finally:
                #close connection before next client
                conn.close()
                print("[SERVER] Connection closed. Waiting for next client. ")
    except KeyboardInterrupt:
        print("\n[SERVER] Shutdown initiated by user.")
    
    finally:
        #clean shutdown
        sock.close()
        print("[SERVER] Sever stopped. All connections closed.")
        

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

    Raises:
        ValueError: If cryptographic validation fails
        ConnectionError: If network/connection issues occur
    """
    # --- Receive client_hello ---
    #Wait for client's handshake message
    try:
        raw_data = conn.recv(4096)
    except socket.timeout:
        raise ConnectionError("[SERVER] Timeout waiting for client_hello")
    except Exception as e:
        raise ConnectionError("[SERVER] Failed to receive client_hello: {e}")

    if not raw_data:
        raise ConnectionError("[SERVER] Failed to receive client_hello")

    #Decode and parse JSON message    
    try:
        client_hello_json = raw_data.decode("utf-8")
        client_hello = json.loads(client_hello_json)
    except UnicodeDecodeError as e:
        #Non-UTF8 data could indicate attack or corruption
        print(f"[WARNING] Non-UTF8 client_hello received. Possible attack or corruption: {e}")
        conn.close()
        return None
    except json.JSONDecodeError as e:
        #Invalid JSON could indicate attack or protocol error
        print(f"[WARNING] Malformed JSON in client_hello. Possible attack or protocol error: {e}")
        conn.close()
        return None
    except Exception as e:
        print(f"[WARNING] Malformed or non-UTF8 client_hello received. Possible attack. Error: {e}")
        conn.close()
        return None

    print(f"[SERVER] Received client_hello: {client_hello}")

    # --- Parse information from client_hello ---
    try:
        client_device_id, client_pubkey_bytes, client_signature = parse_client_hello(client_hello_json)
    except KeyError as e:
        raise ValueError(f"[SERVER] Missing required field in client_hello: {e}")
    except ValueError as e:
        raise ValueError(f"[SERVER] Invalid data format in client_hello: {e}")
    except Exception as e:
        raise ValueError(f"[SERVER] Failed to parse client_hello")
    
    print(f"[SERVER] Client device_id: {client_device_id}")
    print(f"[SERVER] Client ECDH public key ({len(client_pubkey_bytes)} bytes)")

    # --- Verifying Client's RSA signature ---
    #Retrieving the client's trusted RSA Public key from the trust store. 
    try:
        client_rsa_public_key = identity.get_peer_public_key(client_device_id)
    except ValueError as e:
        raise ValueError(f"[SERVER] Unknown or untrusted client '{client_device_id}': {e}")
    except Exception as e: 
        raise ValueError(f"[SERVER] Error retrieving trust key for '{client_device_id}': {e}")
        
    #Verifying that the client's ECDH public key was signed by their legitimate RSA private key. 
    is_valid = verify_ecdh_public_key_signature(
        client_rsa_public_key,
        client_pubkey_bytes,
        client_signature
    )

    if not is_valid:
        #Signature verification failed - possible MITM attack or wrong client.
        raise ValueError(f"[SERVER] RSA signature verification has FAILED fpr client '{client_device_id}'. Rejecting connection.")
    
    print("[SERVER] Client authentification successful via RSA signature.")

    # --- Generate server's ECDH key pair
    #Ephemeral keys created each session for forward secrecy
    server_ecdh = ECDHKeyPair()
    server_pubkey_bytes = server_ecdh.public_bytes()
    print(f"[SERVER] Generated server ECDH key pair ({len(server_pubkey_bytes)} bytes)")

    # --- Compute shared secret ---
    try:
        shared_secret = server_ecdh.compute_shared_secret(client_pubkey_bytes)
    except ValueError as e:
        raise ValueError(f"[SERVER] Invalid client ECDH public key: {e}")

    print(f"[SERVER] Shared secret computed ({len(shared_secret)} bytes)")

    # --- Key derivation ---
    #HKDF to derive a proper AES-256 session key
    session_key = derive_session_key(shared_secret)
    print(f"[SERVER] Session key derived ({len(session_key)} bytes)")

    # --- Build server_hello ---
    #Sign the ECDH public key bytes with the server's RSA private key
    server_signature = sign_ecdh_public_key(identity.private_key, server_pubkey_bytes)

    #Build server_hello message
    server_hello = build_server_hello(identity.device_id, server_pubkey_bytes, server_signature)

    #Send to client over TCP
    try:
        conn.sendall(server_hello.encode("utf-8"))
    except Exception as e:
        raise ConnectionError(f"[SERVER] Failed to send server_hello: {e}")
    
    print(f"[SERVER] Sent server_hello to client.")

    #Handshake complete: return the derived session key
    return session_key


