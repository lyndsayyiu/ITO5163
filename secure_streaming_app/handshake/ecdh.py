"""
ecdh.py

Elliptic Curve Diffie-Hellman (ECDH) key exchange using Curve 25519.

This module provides ephemeral key pair generation and shared secret computation for establishing secure session keys between client & server. 
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class ECDHKeyPair:
    """
    Represents an ephemeral key pair Elliptic Curve Diffie-Hellman (ECDH) key exchange (using Curve25519). 
    
    Curve25519 has been chosen as it provides:
        - 128-bit security level
        - Fast key generation and exchange operations
        - Resistance to side-channel attacks

    The ephmeral nature (generated fresh each session) also provides forward secrecy and compromise of long-term keys doesn't affect past session keys. 

    This class generates:
        - a private key
        - a corresponding public key

    The public key can be transmitted in raw byte form.
    The class can also compute the shared secret using the peer's public key bytes. 
    """
    def __init__(self):
        """
        Generates the key pair object.

        Steps:
            1. Generates a random 32-byte private key (scalar value on Curve25519)
            2. Public key is then derived by scalar multiplication of the curve's base point. 

        Attributes:
            - self.private_key: A private X25519 ECDH key.
            - self.public_key: The corresponding public key

        These keys are used during the authenticated ECDH handshake to establish a shared secret that both parties can independently compute. 
        """
        #Generate a random 32-byte private key
        self.private_key = x25519.X25519PrivateKey.generate()

        #Derive the public key through elliptic curve point multiplication. 
        self.public_key = self.private_key.public_key() 

    def public_bytes(self) -> bytes:
        """
        Serialises the public key into raw 32-byte format for network transmission. 
        This format is suitable for sending over a network during a handshake and matches the standard X25519 raw encoding.

        Returns:
            bytes: The x25519 public key as a 32-byte string in 'raw' bytes. 
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
            )

    def compute_shared_secret(self, peer_public_bytes):
        """
        Computes the ECDH shared secret using the peer's public key.

        Steps:
            1. Converts the peer's raw 32-bytes public key into an X25519PublicKey object. 
            2. Performs scalar multiplication: private_key * peer_public_key
            3. Returns the shared_secret (32 bytes)
        
        Arguments:
            peer_public_bytes (bytes): The peer's 32-byte X25519 public key in raw format (received during handshake) 

        Returns:
            shared_secret (bytes): The shared secret in raw 32-bytes. This will be passed into an HKDF function to derive the final session encryption key. 
                                   Should not be used directly as encryption key
        
        Raises:
            ValueError: If peer_public_bytes is not exactly 32 bytes
            ValueError: If peer_public_bytes represents an invalid curve point. 
        """
        #Reconstruct the peer's public key as a X25519 public key
        #This validates that the bytes represent a valid point on Curve25519
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)

        #Perform the ECDH operation:
        shared_secret = self.private_key.exchange(peer_public_key)
        
        return shared_secret