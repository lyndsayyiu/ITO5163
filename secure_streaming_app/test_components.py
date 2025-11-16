"""
A dummy script to test some of the modules completed so far. 
"""
from handshake.ecdh import ECDHKeyPair
from handshake.key_derivation import derive_session_key
from handshake.rsa_auth import sign_ecdh_public_key, verify_ecdh_public_key_signature
from handshake.identity import load_private_key, load_public_key
from crypto.aes_gcm import encrypt_message, decrypt_message
from streaming.data_source import DataSource

def main():
    print("Testing ECDH Key Exchange")
    client_ecdh = ECDHKeyPair()
    server_ecdh = ECDHKeyPair()

    client_shared = client_ecdh.compute_shared_secret(server_ecdh.public_bytes())
    server_shared = server_ecdh.compute_shared_secret(client_ecdh.public_bytes())

    print("Client shared == Server shared:", client_shared == server_shared)

    #Derive AES session key
    session_key = derive_session_key(client_shared)
    print("Derived session key (32 bytes):", len(session_key), "bytes")

    print("Testing RSA Signing/Verification")
    #Loading keys from storage
    client_priv = load_private_key("storage/rsa_keys/client_private.pem")
    client_pub = load_public_key("storage/rsa_keys/client_public.pem")

    data_to_sign = b"test-ecdh-public-key"
    signature = sign_ecdh_public_key(client_priv, data_to_sign)

    print("Signature created:", len(signature), "bytes")
    print("Signature verifies:", verify_ecdh_public_key_signature(client_pub, data_to_sign, signature))

    print("Testing AES-GCM Encryption/Decryption")
    plaintext = b"This is a test message"
    nonce, ciphertext, tag = encrypt_message(session_key, plaintext)
    recovered = decrypt_message(session_key, nonce, ciphertext, tag)

    print("Recovered plaintext:", recovered.decode())
    print("AES-GCM Working:", recovered == plaintext)

    print("Testing Data Source")
    ds = DataSource()
    msg1 = ds.next_message()
    msg2 = ds.next_message()

    print("Generated messages:")
    print(msg1)
    print(msg2)

    print("Test completed")

if __name__ == "__main__":
    main()
