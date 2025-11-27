import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12 #NIST recommendation of 96-bits
TAG_SIZE = 16 #128-bit authentication tag
KEY_SIZE = 32 #256-bit AES Key 

def encrypt_message(session_key: bytes, plaintext_bytes: bytes):
    """
    Encrypt a plain-text message using AES-GCM.

    Arguments:
        session_key: 256-bit AES Key (Derived from HKDF)
        plaintext_bytes: The plaintext to encrpyt.

    Returns:
        (nonce_bytes, ciphertext_bytes, tag_bytes)
    """
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"Session Key must be {KEY_SIZE} bytes long")
    
    # AES-GCM requires a new random nonce for each message under the same key. 
    nonce_bytes = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(session_key)

    cipher_tag = aesgcm.encrypt(
        nonce_bytes,
        plaintext_bytes,
        associated_data=None
    )

    #Splitting to cipher and tag individually as AESGCM.encrypt() returns the cipher with the tag appended. 
    ciphertext_bytes = cipher_tag[:-TAG_SIZE]
    tag_bytes = cipher_tag[-TAG_SIZE:]

    return nonce_bytes, ciphertext_bytes, tag_bytes

def decrypt_message(session_key: bytes, nonce_bytes: bytes, ciphertext_bytes: bytes, tag_bytes: bytes) -> bytes:
    """
    Decrypts a ciphertext message using AES-GCM. 

    Arguments:
        session_key: 258-bit AES Key (Derived from HKDF)
        nonce_bytes: The nonce used during encryption.
        ciphertext_bytes: The ciphertext to be decrypted.
        tag_bytes: The authentication tag.

    Returns:
        The decrypted plaintext (bytes)

    Raises:
        Exception if authentication fails (from AESGCM) if there is tampering/wrong key/wrong nonce.
    """
    if len(session_key) != KEY_SIZE:
        raise ValueError(f"Session key must be {KEY_SIZE} bytes long.")
    if len(nonce_bytes) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes long.")
    if len(tag_bytes) != TAG_SIZE:
        raise ValueError(f"Tag must be {TAG_SIZE} bytes long.")
    
    aesgcm = AESGCM(session_key)

    #Recombining ciphertext and tag
    cipher_tag = ciphertext_bytes + tag_bytes

    try:
        plaintext_bytes = aesgcm.decrypt(
            nonce_bytes,
            cipher_tag,
            associated_data=None
        )
        return plaintext_bytes
    except Exception as e:
        raise ValueError(f"Decryption failed - possible tampering or key mismatch: {e}")
    
def validate_key_material(session_key: bytes) -> bool:
    """
    Validates that the session key meets security requirements. 

    Arguments:
        session_key (bytes): The session key to validate.

    Returns:
        bool: True if key appears valid, False otherwise. 
    """
    if len(session_key) != KEY_SIZE:
        return False
    
    #Check for all-zero key (indicates derivation failure)
    if session_key == b'\x00' * KEY_SIZE:
        return False
    
    #Check for sufficient entropy
    unique_bytes = len(set(session_key))
    if unique_bytes < 16: #Less than 16 unique bytes would be suspicious.
        return False
    
    return True
