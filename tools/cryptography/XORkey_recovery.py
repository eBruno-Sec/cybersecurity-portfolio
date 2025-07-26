import base64

# Original base64 cookie from Natas11 to inteded cookie
original_cookie_b64 = input("Gimme the cookie? ")
known_plaintext = '{"showpassword":"no","bgcolor":"#ffffff"}'
new_plaintext = '{"showpassword":"yes","bgcolor":"#ffffff"}'

# Decode original cookie to get encrypted bytes
encrypted_bytes = base64.b64decode(original_cookie_b64)


recovered_key = ''.join(
    chr(encrypted_bytes[i] ^ ord(known_plaintext[i]))
    for i in range(len(known_plaintext))
)

# Try to detect repeating pattern in the key
def detect_repeating_key(full_key):
    for i in range(1, len(full_key)):
        repeat = full_key[:i]
        if repeat * (len(full_key) // len(repeat)) == full_key[:len(repeat) * (len(full_key) // len(repeat))]:
            return repeat
    return full_key  # fallback if no repeat pattern found

xor_key = detect_repeating_key(recovered_key)
print(f"[+] Recovered XOR Key: {xor_key}")

# XOR encrypt the new data using the recovered key
def xor_encrypt(data, key):
    return ''.join(
        chr(ord(data[i]) ^ ord(key[i % len(key)]))
        for i in range(len(data))
    )

# Encrypt and encode new payload
new_encrypted = xor_encrypt(new_plaintext, xor_key)
forged_cookie = base64.b64encode(new_encrypted.encode()).decode()
print(f"[+] Forged Cookie Value:\n{forged_cookie}")
