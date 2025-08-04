#!/usr/bin/env python3
"""
XOR Key Recovery Tool

⚠️ EDUCATIONAL PURPOSE ONLY ⚠️
This tool demonstrates XOR key recovery techniques for cryptographic analysis.
Originally designed for OverTheWire Natas11 challenge.

Usage: python3 XORkey_recovery.py
"""

import base64
import sys


def main():
    print("=" * 50)
    print("XOR KEY RECOVERY TOOL")
    print("=" * 50)
    print("⚠️  Educational/Authorized Testing Only ⚠️")
    print()
    
    try:
        # Get input from user
        original_cookie_b64 = input("Enter the base64 encoded cookie: ").strip()
        
        if not original_cookie_b64:
            print("[!] Error: No cookie provided")
            sys.exit(1)
            
        # Known plaintexts for Natas11 challenge
        known_plaintext = '{"showpassword":"no","bgcolor":"#ffffff"}'
        new_plaintext = '{"showpassword":"yes","bgcolor":"#ffffff"}'

        # Decode original cookie to get encrypted bytes
        try:
            encrypted_bytes = base64.b64decode(original_cookie_b64)
        except Exception as e:
            print(f"[!] Error decoding base64: {e}")
            sys.exit(1)
        
        # Recover the XOR key by XORing known plaintext with ciphertext
        if len(encrypted_bytes) < len(known_plaintext):
            print("[!] Error: Encrypted data too short")
            sys.exit(1)
            
        recovered_key = ''.join(
            chr(encrypted_bytes[i] ^ ord(known_plaintext[i]))
            for i in range(len(known_plaintext))
        )

        # Try to detect repeating pattern in the key
        xor_key = detect_repeating_key(recovered_key)
        print(f"[+] Recovered XOR Key: '{xor_key}'")
        print(f"[+] Key Length: {len(xor_key)} bytes")
        
        # Encrypt and encode new payload
        new_encrypted = xor_encrypt(new_plaintext, xor_key)
        forged_cookie = base64.b64encode(new_encrypted.encode('latin-1')).decode()
        
        print(f"\n[+] Original Plaintext: {known_plaintext}")
        print(f"[+] Target Plaintext:   {new_plaintext}")
        print(f"[+] Forged Cookie Value:\n{forged_cookie}")
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


def detect_repeating_key(full_key):
    """Detect repeating pattern in the recovered key."""
    for i in range(1, len(full_key)):
        repeat = full_key[:i]
        if repeat * (len(full_key) // len(repeat)) == full_key[:len(repeat) * (len(full_key) // len(repeat))]:
            return repeat
    return full_key  # fallback if no repeat pattern found


def xor_encrypt(data, key):
    """XOR encrypt data with the given key."""
    return ''.join(
        chr(ord(data[i]) ^ ord(key[i % len(key)]))
        for i in range(len(data))
    )


if __name__ == "__main__":
    main()
