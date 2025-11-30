# Secure Streaming Application

A secure client-server streaming system using ECDH key exchange, RSA authentication, and AES-GCM encryption to demonstrate network security principles including forward secrecy and mutual authentication.

## Overview

The client generates sequential messages and sends them encrypted to the server. The server receives, decrypts, and validates the messages. Security is provided through:
- RSA signatures for device authentication
- ECDH (Curve25519) for ephemeral key exchange (forward secrecy)
- HKDF for session key derivation
- AES-256-GCM for authenticated encryption

## Requirements

- Python 3.8 or higher
- `cryptography` library

## Installation

```bash
cd secure_streaming_app
pip install cryptography
```

RSA keys are pre-generated in `storage/rsa_keys/`. To regenerate:
```bash
python utils/generate_rsa_keys.py
python utils/create_trust_store.py
```

## Running the Application

**Terminal 1 - Start Server:**
```bash
python run_server.py
```

**Terminal 2 - Start Client:**
```bash
python run_client.py
```

**Configuration:** Update `SERVER_IP` in `run_client.py` if testing across machines (default: `127.0.0.1` for local testing).

**Stop:** Press `Ctrl+C` in either terminal.

## Attack Demonstrations

Scripts in `testing/` demonstrate security properties. Attack demonstrations use port 8888 for attacker proxy, port 5050 for real server.

### 1. Untrusted Device
Tests trust store access control.
```bash
python run_server.py                    # Terminal 1
python testing/run_untrusted_client.py  # Terminal 2
```
**Result:** Handshake fails - device not in trust store.

### 2. Device Impersonation
Tests RSA signature validation.
```bash
python run_server.py                         # Terminal 1
python testing/run_client_impersonation.py   # Terminal 2
```
**Result:** Handshake fails - attacker cannot forge valid RSA signature.

### 3. Message Tampering
Tests AES-GCM integrity protection.
```bash
python run_server.py               # Terminal 1
python run_client.py               # Terminal 2 (let run briefly)
python testing/test_tampered.py    # Terminal 3
```
**Result:** Tampered messages rejected - authentication tag verification fails.

### 4. Replay Attack
Tests sequence number validation.
```bash
python run_server.py              # Terminal 1
python run_client.py              # Terminal 2 (stop after a few messages)
python testing/attack_replay.py   # Terminal 3
```
**Result:** Replayed messages rejected - sequence numbers prevent replay.

### 5. Message Injection (MITM Simulation)
Tests complete attack resistance.
```bash
python run_server.py                  # Terminal 1
python testing/attack_injection.py    # Terminal 2
# Edit run_client.py: SERVER_PORT = 8888
python run_client.py                  # Terminal 3
```
**Result:** Attacker can forward but cannot inject, decrypt, or modify messages.

### 6. Forward Secrecy
Tests that RSA key compromise doesn't expose past sessions.

**Why it works:** ECDH private keys are ephemeral (destroyed after handshake). Even with RSA keys and captured traffic, attackers cannot recover ECDH private keys to derive past session keys.

## Key Security Features

- **Authentication:** RSA-2048 signatures + trust store
- **Confidentiality:** AES-256-GCM encryption
- **Integrity:** GCM authentication tags
- **Forward Secrecy:** Ephemeral ECDH keys (Curve25519)
- **Replay Protection:** Monotonic sequence numbers

## Project Structure

```
secure_streaming_app/
├── crypto/
│   ├── __init__.py
│   ├── aes_gcm.py
│   └── secure_channel.py
├── handshake/
│   ├── __init__.py
│   ├── ecdh.py
│   ├── identity.py
│   ├── key_derivation.py
│   └── rsa_auth.py
├── storage/
│   ├── rsa_keys/
│   │   ├── client_private.pem
│   │   ├── client_public.pem
│   │   ├── server_private.pem
│   │   └── server_public.pem
│   └── trust_store.json
├── streaming/
│   ├── __init__.py
│   ├── data_source.py
│   ├── protocol.py
│   ├── stream_client.py
│   └── stream_Server.py
├── testing/
│   ├── attack_impersonation.py
│   ├── attack_injection.py
│   ├── attack_replay.py
│   ├── replay_from_pcap.py
│   ├── run_client_impersonation.py
│   ├── run_untrusted_client.py
│   ├── test_fake_signature.py
│   ├── test_malformed.py
│   └── test_tampered.py
├── utils/
│   ├── create_trust_store.py
│   └── generate_rsa_keys.py
├── capture.pcap
├── run_client.py # --- Start client program from here.
└── run_server.py # --- Start server program with this file. 
```

## Known Limitations

- Single client support (no concurrent connections)
- No automatic session key rotation
- Static trust store (no runtime revocation)
- No rate limiting or connection throttling

## Troubleshooting

**Connection Refused:** Verify server is running and SERVER_IP is correct in run_client.py

**Invalid RSA Signature:** Ensure RSA keys match trust_store.json entries

**Import Errors:** Run from project root directory (secure_streaming_app/)
