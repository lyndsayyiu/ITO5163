import json
import struct
import socket
from typing import Tuple, Dict, Any

from crypto.aes_gcm import encrypt_message, decrypt_message, validate_key_material
from streaming.protocol import build_encrypted_data_message, parse_encrypted_data_message

SOCKET_TIMEOUT = 30 #seconds - prevents indefinite blocking
MAX_MESSAGE_SIZE = 10 * 1024 * 1024 #10 MB - prevent memory exhaustion
MIN_MESSAGE_SIZE = 10 #bytes to prevent trivial messages

#Internal helpers for framing
def _send_with_length_prefix(sock, data_bytes: bytes):
    """
    Sends a message over a TCP socket.

    Uses a 4-byte big-endian length prefix to ensure that the receiver can determine exactly 
    how many bytes belong to the current message. This avoids message-boundary issues in stream-based TCP communication. 

    Arguments:
        sock: A connected TCP socket object. 
        data_bytes (bytes): The raw message bytes to send. 
    """
    if len(data_bytes) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message size {len(data_bytes)} exceeds maximum {MAX_MESSAGE_SIZE}")
    
    if len(data_bytes) < MIN_MESSAGE_SIZE:
        raise ValueError(f"Message size {len(data_bytes)} below minimum {MIN_MESSAGE_SIZE}")

    length_prefix = struct.pack("!I", len(data_bytes)) #network byte order

    try:
        sock.sendall(length_prefix + data_bytes)
    except socket.timeout:
        raise ConnectionError("Send timeout - network may be congested")
    except OSError as e:
        raise ConnectionError(f"Socket send failed: {e}")


def _recv_exact_len(sock, length: int) -> bytes:
    """
    Reads exactly 'length' bytes from a TCP socket.

    Calls sock.recv() repeatedly until the requested number of bytes has been read. 
    This ensures the full message is retrieved. 

    Arguments:
        sock: A connected TCP socket object. 
        length (int): The exact number of bytes to read.

    Returns:
        bytes: A byte string containing exactly 'length' bytes. 

    Raises:
        ConnectionError: If the socket closes before the 'length' bytes are read. 
        ValueError: If 'length' is negative. 
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Requested length {length} exceeds maximum {MAX_MESSAGE_SIZE}")
    
    chunks = []
    bytes_read = 0

    while bytes_read < length:
        try:
            chunk = sock.recv(length - bytes_read)
        except socket.timeout:
            raise ConnectionError(f"Receive timeout after {bytes_read}/{length} bytes")
        
        if chunk == b"":
            raise ConnectionError("Socket closed unexpectedly while receiving data.")
        chunks.append(chunk)
        bytes_read += len(chunk)
    
    return b"".join(chunks)

def _recv_with_length_prefix(sock) -> bytes:
    """
    Receives a length-prefixed message from a TCP socket.

    The function reads the 4-byte big-endian unsigned integer to indicate the message length.
    Then reads exactly that many bytes using the _recv_exact() function. 

    Arguments:
        sock: A connected TCP socket object.

    Returns:
        bytes: The raw message bytes.

    Raises:
        ConnectionError: If the socket closes prematurely.
        struct.error: If the length prefix is invalid. 
    """
    # Read the 4-byte length and determine message length. 
    try:
        length_prefix = _recv_exact_len(sock, 4)
    except ConnectionError as e:
        raise ConnectionError(f"Failed to read message length prefix: {e}")
    
    try:
        (msg_length,) = struct.unpack("!I", length_prefix)
    except struct.error as e:
        raise ValueError(f"Invalid length prefix format: {e}")
    
    #Validate message length
    if msg_length < MIN_MESSAGE_SIZE:
        raise ValueError(f"Message length {msg_length} below minimum {MIN_MESSAGE_SIZE}")
    
    if msg_length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message length {msg_length} exceeds maximum {MAX_MESSAGE_SIZE}. Possible attack/corruption.")
    
    #Read the full message
    return _recv_exact_len(sock, msg_length)

#Public methods

def secure_send(sock, session_key: bytes, seq: int, message_dict: dict):
    """
    Encrypts and sends an AES-GCM encrypted message over a TCP socket. 

    The message is serialised from a Python dict to JSON
    Encrypts the JSON bytes with AES-GCM using the given session key. 
    Wraps the encrypted fields and sequence number into a JSON packet. 
    Sends the packet over the socket with a 4-byte big-endian length prefix.

    Arguments:
        sock: A connected TCP socket object. 
        session_key (bytes): A 32-byte AES session key.
        seq (int): The sequence number for this message, used by higher-level logic for ordering and replay detection. 
        message_dict (dict): The plaintext message to send. This will be JSON-encoded before encryption.

    Raises:
        ValueError: If the session_key is not the expected length (handled in encrypt_message).
        OSError: If the underlying socket encounters a send error.
        TypeError: If message_dict is not JSON-serialisable.
    """
    #validating Key before use. 
    if not validate_key_material(session_key):
        raise ValueError("Invalid session key material")
    
    if seq < 1:
        raise ValueError(f"Sequence number must be positive, got {seq}")
    
    #Validate message dict
    if not isinstance(message_dict, dict):
        raise TypeError(f"Message must be dict, got {type(message_dict)}")
    
    try:
        #Converting the plaintext to JSON
        plaintext_bytes = json.dumps(message_dict).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ValueError(f"Message is not JSON-serialisable: {e}")
    
    #Encrypting with AES-GCM
    try:
        nonce_bytes, ciphertext_bytes, tag_bytes = encrypt_message(
            session_key,
            plaintext_bytes
        )
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")

    #Wrap into JSON packet
    encrypted_json = build_encrypted_data_message(
        seq,
        nonce_bytes,
        ciphertext_bytes,
        tag_bytes
    )

    #Sending the packet over the socket
    _send_with_length_prefix(sock, encrypted_json.encode("utf-8"))

def secure_receive(sock, session_key: bytes):
    """
    Receives and decrypts a message over a TCP socket using AES-GCM. 

    Reads a JSON packet from the socket
    Parses the encrypted packet to extract the seq, nonce, ciphertext and tag.
    Uses the information to decrypt the ciphertext using AES-GCM and the provided session key.
    Deserialises the resulting JSON plaintext into a Python dict. 
    
    Arguments:
        sock: A connected TCP socket object. 
        session_key (bytes): A 32-byte AES session key (matching the one used by the sender)

    Returns:
        tuple[int, dict]:
            A pair (seq, message_dict):
                - seq (int): The sequence number from the encrypted packet.
                - message_dict: The decrypted message. 

    Raises:
        ConnectionError: If the socket closes or times out before the full message is read. 
        ValueError: If the session_key, nonce, or tag lengths are invalid. 
        cryptography.exceptions.InvalidTag: If the decryption fails due to authentication/tag mismatch.
        json.JSONDecodeError: If the decrypted plaintext is not a valid JSON. 

    Notes:
        A failed decrpytion (InvalidTag) would be a strong indicator or tampering, corruption or that the session key is mismatched. 
    """
    #Validate key before use
    if not validate_key_material(session_key):
        raise ValueError("Invalid session key material")
    
    #Receive the encrpyted JSON bytes
    try:
        json_bytes = _recv_with_length_prefix(sock)
    except (ConnectionError, ValueError) as e:
        raise ConnectionError(f"Failed to receive message: {e}")
    
    #Decode to string
    try:
        json_str = json_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"Message is not valid UTF-8: {e}")
    
    #Extract encrypted fields
    try:
        seq, nonce_bytes, ciphertext_bytes, tag_bytes = parse_encrypted_data_message(json_str)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise ValueError(f"Invalid encrpyted message format: {e}")
    
    #Validate sequence number
    if seq < 1:
        raise ValueError(f"Invalid sequence number: {seq}")

    #Decrypt using AES-GCM
    try:
        plaintext_bytes = decrypt_message(
            session_key,
            nonce_bytes,
            ciphertext_bytes,
            tag_bytes
        )
    except Exception as e:
        raise ValueError(f"Decryption failed at seq={seq}. Possible tampering, key mismatch or network corruption: {e}")
    
    #Convert to dict
    try:
        message_dict = json.loads(plaintext_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Decrypted message is not valid JSON: {e}")
    
    if not isinstance(message_dict, dict):
        raise ValueError(f"Decrpyted message is not a dict: {type(message_dict)}")

    return seq, message_dict

    


