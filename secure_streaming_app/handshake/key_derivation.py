"""
key_derivation.py

This module derives cryptographically strong session keys form the raw shared secret produced by the X25519 key exchange. 
The ECDH shared secret should not be used directly as an encryption key and should be processed through a Key Derivation Function (KDF). 

HKDF (HMAC-based Key Derivation Function) provides:
    - Extraction: Converts the ECDH shared secret into uniformly random key material
    - Expansion: Derives the final session key with proper length and entropy
    - Domain separation: The 'info' parameters binds the key to the handshake context. 

SHA-256 is used as the hashing algorithm to provide 128-bit security stregth.
"""
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derives a 256-bit AES session key from an ECDH shared secret using HKDF.

    Notes:
        - No salt is used (salt=None) as the ECDH shared secret has sufficient entropy.
    
    Arguments: 
        shared_secret (bytes): The 32-byte ECDH shared secret computed from key exchange.
    
    Returns:
        bytes: A 32-byte (256-bits) session key with uniform randomness, suitable for use with AES-GCM encryption. 
    """
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length = 32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    return derived_key