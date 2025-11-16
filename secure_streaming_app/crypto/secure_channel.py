import json
import struct

from crypto.aes_gcm import encrypt_message, decrypt_message
from streaming.protocol import build_encrypted_data_message, parse_encrypted_data_message

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
    length_prefix = struct.pack("!I", len(data_bytes)) #network byte order
    sock.sendall(length_prefix + data_bytes)

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
    
    chunks = []
    bytes_read = 0

    while bytes_read < length:
        chunk = sock.recv(length - bytes_read)
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
    length_prefix = _recv_exact_len(sock, 4)
    (msg_length,) = struct.unpack("!I", length_prefix)

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
    #Converting the plaintext to JSON
    plaintext_bytes = json.dumps(message_dict).encode("utf-8")

    #Encrypting with AES-GCM
    nonce_bytes, ciphertext_bytes, tag_bytes = encrypt_message(
        session_key,
        plaintext_bytes
    )

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
        ConnectionError: If the socket closes before the full message is read. 
        ValueError: If the session_key, nonce, or tag lengths are invalid. 
        cryptography.exceptions.InvalidTag: If the decryption fails due to authentication/tag mismatch.
        json.JSONDecodeError: If the decrypted plaintext is not a valid JSON. 

    Notes:
        A failed decrpytion (InvalidTag) would be a strong indicator or tampering, corruption or that the session key is mismatched. 
    """
    #Receive the encrpyted JSON bytes
    json_bytes = _recv_with_length_prefix(sock)
    json_str = json_bytes.decode("utf-8") #convert to str

    #Extract encrypted fields
    seq, nonce_bytes, ciphertext_bytes, tag_bytes = parse_encrypted_data_message(json_str)

    #Decrypt using AES-GCM
    plaintext_bytes = decrypt_message(
        session_key,
        nonce_bytes,
        ciphertext_bytes,
        tag_bytes
    )

    #Convert to dict
    message_dict = json.loads(plaintext_bytes.decode("utf-8"))

    return seq, message_dict
    


