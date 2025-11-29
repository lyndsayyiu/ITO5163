from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_keypair(private_path: str, public_path:str):
    """
    Generates an RSA key pair and writes the private and public keys to disk. 
    """
    #Generating the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    #Writing private key to file (PEM, PKCS8, no password)
    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    #Generating the public key
    public_key = private_key.public_key()

    #Writing public key to file
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    print(f"Generated keypair:\n {private_path}\n {public_path}\n")

def main():
    #Ensuring that the directory exists
    os.makedirs("storage/rsa_keys", exist_ok=True)

    print("Generating RSA Key Pairs...")

    #Generating client key pairs
    generate_rsa_keypair(
        "storage/rsa_keys/client_private.pem",
        "storage/rsa_keys/client_public.pem"
    )

    #Generate server key pair
    generate_rsa_keypair(
        "storage/rsa_keys/server_private.pem",
        "storage/rsa_keys/server_public.pem"
    )

    print("All RSA key pairs generated successfully.")

if __name__ == "__main__":
    main()