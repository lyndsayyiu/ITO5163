from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class ECDHKeyPair:
    def __init__(self):
        # TO-DO: initialise the public and private key
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_bytes(self):
        # TO-DO:return public keys in bytes
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
            )

    def compute_shared_secret(self, peer_public_bytes):
        #To-do: compute shared secret
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret