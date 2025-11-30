"""
protocol.py

This module defines the message formats and serialisation functions for the secure streaming app. All messages are transmitted as JSON strings over TCP,
with binary data (cryptographic keys, signatures, ciphertexts) encoded in Base64 for safe transmission. 

This module defines three message types:
    1. client_hello: Initial handshake message from client to server
        - Contains: device_id, ECDH public key, RSA signature
        - Purpose: Authenticate client and initiate key exchange

    2. server_hello: Handshake response from server to client
        - Contains: device_id, ECDH public key, RSA signature
        - Purpose: Authenticate server and complete key exchange

    3. data: Encrypted application data messages
        - Contains: sequence number, nonce, ciphertext, authentication tag
        - Purpose: Securely transmit application messages using AES-GCM

Base64 encoding ensures binary cryptographic data can be safely transmissted in JSON without encoding issues or data corruption. 
"""
import json
import base64

#Base64 helper methods
def b64_encode(data: bytes) -> str:
    """
    Encodes raw bytes into a URL-safe base64 string (UTF-8).
    """
    return base64.b64encode(data).decode("utf-8")

def b64_decode(data_str: bytes) -> str:
    """
    Decodes a base64 string (UTF-8) back into raw bytes.
    """
    return base64.b64decode(data_str.encode("utf-8"))

#Client Hello Message
def build_client_hello(device_id: str, ecdh_public_key_bytes: bytes, signature_bytes: bytes) -> str:
    """
    Builds a JSON message for the client's handshake initiation. 
    Returns the JSON string
    """
    message = {
        "type": "client_hello",
        "device_id": device_id,
        "ecdh_public_key": b64_encode(ecdh_public_key_bytes),
        "signature": b64_encode(signature_bytes)
    }
    return json.dumps(message)

def parse_client_hello(json_str: str):
    """
    Parse a client_hello JSON message.
    Returns: (device_id, ecdh_public_key_bytes, signature_bytes)
    """
    data = json.loads(json_str)

    if data.get("type") != "client_hello":
        raise ValueError("Not a client message")
    
    device_id = data["device_id"]
    ecdh_public_key_bytes = b64_decode(data["ecdh_public_key"])
    signature = b64_decode(data["signature"])

    return device_id, ecdh_public_key_bytes, signature

#Server Hello Message
def build_server_hello(device_id: str, ecdh_public_key_bytes: bytes, signature_bytes: bytes) -> str:
    """
    Builds a JSON message for the server's handshake reply. 
    Returns the JSON string
    """
    message = {
        "type": "server_hello",
        "device_id": device_id,
        "ecdh_public_key": b64_encode(ecdh_public_key_bytes),
        "signature": b64_encode(signature_bytes)
    }
    return json.dumps(message)

def parse_server_hello(json_str: str):
    """
    Parse a server_hello JSON message.
    Returns: (device_id, ecdh_public_key_bytes, signature_bytes)
    """
    data = json.loads(json_str)

    if data.get("type") != "server_hello":
        raise ValueError("Not a server_hello message")
    
    device_id = data["device_id"]
    ecdh_public_key_bytes = b64_decode(data["ecdh_public_key"])
    signature_bytes = b64_decode(data["signature"]) 

    return device_id, ecdh_public_key_bytes, signature_bytes

#Encrypted Data Message
def build_encrypted_data_message(seq: int, nonce_bytes: bytes, ciphertext_bytes: bytes, tag_bytes: bytes) -> str:
    """
    Builds a JSON message for the encrypted streaming data. 
    Returns a JSON string. 
    """
    message = {
        "type": "data",
        "seq": seq,
        "nonce": b64_encode(nonce_bytes),
        "ciphertext": b64_encode(ciphertext_bytes),
        "tag": b64_encode(tag_bytes)
    }
    return json.dumps(message)

def parse_encrypted_data_message(json_str: str):
    """
    Parses the encrypted data message. 
    Returns (seq, nonce_bytes, ciphertext_bytes, tag_bytes)
    """
    data = json.loads(json_str)

    if data.get("type") != "data":
        raise ValueError("Not a data message")
    
    seq = data["seq"]
    nonce_bytes = b64_decode(data["nonce"])
    ciphertext_bytes = b64_decode(data["ciphertext"])
    tag_bytes = b64_decode(data["tag"])

    return seq, nonce_bytes, ciphertext_bytes, tag_bytes