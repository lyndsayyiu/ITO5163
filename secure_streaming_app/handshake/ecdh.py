from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class ECDHKeyPair:
    """
    Represents a keypair using an Elliptic Curve Diffie-Hellman Key Exchange (using Curve25519).

    This class generates:
        - a private key
        - a corresponding public key

    The public key can be transmitted in raw byte form.
    The class can also compute the shared secret using the peer's public key bytes. 
    """
    def __init__(self):
        """
        Generates the key pair object.

        Attributes:
            - self.private_key: A private X25519 ECDH key.
            - self.public_key: The corresponding public key

        These keys are used for authenticated ECDH Key Exchange during the handshake. 
        """
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_bytes(self):
        """
        Returns the public key in raw 32-byte format. 

        This format is suitable for sending over a network during a handshake and matches the standard X25519 raw encoding.

        Returns:
            bytes: The 32-byte public key. 
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
            )

    def compute_shared_secret(self, peer_public_bytes):
        """
        Computes the ECDH shared secret using the peer's public key (in bytes). 

        Converts the peer's raw 32-bytes public key into an X25519PublicKey object. 
        Performs the Diffie-Hellman Key Exhange

        Arguments:
            peer_public_bytes (bytes): The peer's 32-byte X25519 public key. 

        Returns:
            shared_secret (bytes): The shared secret in raw 32-bytes. This will be passed into an HKDF function to derive the final session encryption key. 
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret