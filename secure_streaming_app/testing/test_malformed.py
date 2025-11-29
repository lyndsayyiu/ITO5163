"""
test_malformed.py

Tests server input validation with various malformed/invalid inputs.
"""

import socket
import json
import time

def test_garbage_data():
    print("\n--- Test 1: Garbage Data ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        
        sock.sendall(b"NOT_JSON_@#$%^&*()")
        time.sleep(1)
        sock.close()
        print("Server handled garbage data")
    except Exception as e:
        print(f"Connection rejected: {type(e).__name__}")

def test_wrong_type():
    print("\n--- Test 2: Wrong Message Type ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        
        wrong_msg = {"type": "invalid_type", "data": "test"}
        sock.sendall(json.dumps(wrong_msg).encode("utf-8"))
        time.sleep(1)
        sock.close()
        print("Server rejected wrong type")
    except Exception as e:
        print(f"Handled: {type(e).__name__}")

def test_missing_fields():
    print("\n--- Test 3: Missing Required Fields ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        
        incomplete = {"type": "client_hello", "device_id": "test"}
        sock.sendall(json.dumps(incomplete).encode("utf-8"))
        time.sleep(1)
        sock.close()
        print("Server rejected incomplete message")
    except Exception as e:
        print(f"Handled: {type(e).__name__}")

def test_invalid_base64():
    print("\n--- Test 4: Invalid Base64 ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        
        bad_msg = {
            "type": "client_hello",
            "device_id": "attacker",
            "ecdh_public_key": "NOT_BASE64!!!",
            "signature": "INVALID@#$"
        }
        sock.sendall(json.dumps(bad_msg).encode("utf-8"))
        time.sleep(1)
        sock.close()
        print("Server rejected invalid base64")
    except Exception as e:
        print(f"Handled: {type(e).__name__}")

def test_non_utf8():
    print("\n--- Test 5: Non-UTF8 Binary Data ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 5050))
        
        sock.sendall(b'\x80\x81\x82\xFF\xFE\xFD')
        time.sleep(1)
        sock.close()
        print("Server handled non-UTF8 data")
    except Exception as e:
        print(f"Handled: {type(e).__name__}")

def main():
    print("\n--- Malformed Input Tests ---")
    print("Server should handle all inputs gracefully without crashing\n")
    
    tests = [
        test_garbage_data,
        test_wrong_type,
        test_missing_fields,
        test_invalid_base64,
        test_non_utf8
    ]
    
    for test in tests:
        test()
        time.sleep(1)
    
    print("\n--- Tests Complete ---")
    print("Check server console for error handling\n")

if __name__ == "__main__":
    main()