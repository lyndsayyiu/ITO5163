"""
identity.py

This module manages the identity of a device and this module manges the long-term RSA identity of devices
and provides access to trusted peer public keys through a trust store mechanism.

Each device has:
    - A unique device_id (str)
    - An RSA private key (str) from PEM file.
    - An RSA public key corresponding to the private key (str) from PEM file
    - A trust store (JSON) mapping trusted peer device_id's to their trusted RSA public keys
"""
from cryptography.hazmat.primitives import serialization
import json

def load_private_key(path: str):
    """
    Loads an RSA private key from a PEM file.
    Returns an RSAPrivateKey object
    """
    with open(path, "rb") as f:
        private_key_data = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None
    )
    return private_key

def load_public_key(path: str):
    """
    Loads an RSA public key from a PEM file. 
    Returns an RSAPublicKey object
    """
    with open(path, "rb") as f:
        public_key_data = f.read()
    public_key = serialization.load_pem_public_key(public_key_data)
    return public_key  

def load_trust_store(path: str) -> dict:
    """
    Loads a trusteed peer public keys from a JSON trust store. 
    The trust store should map the device_id -> PEM public key string
    """
    with open(path, "r") as f:
        trust_data = json.load(f)
    return trust_data

def load_trusted_key(device_id: str, trust_store: dict):
    """
    Takes the device ID and a trust store dictionary.
    Returns an RSA public key object for the trusted peer. 
    """
    if device_id not in trust_store:
        raise ValueError(f"Device ID {device_id} not in trust store.")
    
    pem_string = trust_store[device_id]
    pem_bytes = pem_string.encode("utf-8")

    public_key = serialization.load_pem_public_key(pem_bytes)
    return public_key

class Identity:
    """
    Represents the identity of a device (client or server):
    - device_id: a string label for the device
    - private_key: RSA private key for the device
    - public_key: RSA public key for the device
    - trust_store: A dictionary mapping peer device ID's to PEM public keys

    Provides a method to retrieve the trusted RSA public key for a peer. 
    """
    def __init__(self, device_id: str, private_key_path: str, public_key_path: str, trust_store_path: dict):
        self.device_id = device_id
        self.private_key = load_private_key(private_key_path)
        self.public_key = load_public_key(public_key_path)
        self.trust_store = load_trust_store(trust_store_path)

    def get_peer_public_key(self, peer_id: str):
        """
        Returns a RSA Public Key object for the trusted peer device.
        """
        return load_trusted_key(peer_id, self.trust_store)