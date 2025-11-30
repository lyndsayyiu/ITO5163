"""
rsa_auth.py

This module provides RSA digital signature functions to provide authentication of ephermal ECDH public keys during the handshake.

The authentication process:
    1. The party signs their ephemeral ECDH public key with their long-term RSA private key.
    2. The peer verifies the signature using the RSA public key of the party from peer's trust store. 
    3. Successful verification provdes the ECDH public key came from the legitimate device.

RSA-PSS (Probabilistic Signature Scheme) is used for signing:
    - Uses SHA-256 for hasing and MGF1 for mask generation
    - Maximum salt length for optimal security. 
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_ecdh_public_key(private_key, public_key_bytes: bytes) -> bytes:
    """
    Signs the Elliptal Curve Diffie-Hellman public key bytes using the given RSA private key. 
    Returns the signature as bytes
    """
    signature = private_key.sign(
        public_key_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_ecdh_public_key_signature(public_key, public_key_bytes: bytes, signature: bytes) -> bool:
    """
    Verifies the RSA signature over the ECDH public key bytes. 

    Returns boolean, True if the signature is valid and False if not.
    """
    try:
        public_key.verify(
            signature,
            public_key_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False