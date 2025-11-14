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