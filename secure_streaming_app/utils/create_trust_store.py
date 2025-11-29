"""
create_trust_store.py

Reads the RSA public key files for the client and server and creates a JSON trust store that maps device IDs to their trusted public keys.

This script only needs to be run ONCE during set-up to generate the trust_store.json file. 
The generated trust_store.json file is then committted into the project so that markers do NOT need to run this script.
"""
import json
import os

CLIENT_PUB_PATH = "storage/rsa_keys/client_public.pem"
SERVER_PUB_PATH = "storage/rsa_keys/server_public.pem"
TRUST_STORE_PATH = "storage/trust_store.json"

def read_pem(path: str) -> str:
    """
    Reads a PEM-formatted RSA public key from a file and returns it as a string.

    Arguments:
        path (str): Path to a PEM public key file.

    Returns:
        str: The PEM public key contents as a string.

    Raises:
        FileNotFoundError: If the PEM file does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing PEM file: {path}")
    
    with open(path, "r") as f:
        return f.read()
    
def create_trust_store():
    """
    Loads both the client's and server's RSA public keys, constructs a trust store dictionary mapping device_id -> PEM string
    and writes it to JSON. 

    The trust_store.json file will contain:
        {
            "client": "<client RSA PUBLIC KEY>"
            "server": "<server RSA PUBLIC KEY>"
        }
    """
    print("Reading public keys...")

    client_pub = read_pem(CLIENT_PUB_PATH)
    server_pub = read_pem(SERVER_PUB_PATH)

    trust_store = {
        "client": client_pub,
        "server": server_pub
    }

    print("Writing trust_store.json...")
    with open(TRUST_STORE_PATH, "w") as f:
        json.dump(trust_store, f, indent=4)

    print(f"trust_store.json created successfully at {TRUST_STORE_PATH}")

if __name__ == "__main__":
    create_trust_store()
