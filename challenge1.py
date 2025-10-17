import binascii

# Given hex strings
k1_hex = "3c3f0193af37d2ebbc50cc6b91d27cf61197"
k21_hex = "ff76edcad455b6881b92f726987cbf30c68c"
k23_hex = "611568312c102d4d921f26199d39fe973118"
k1234_hex = "91ec5a6fa8a12f908f161850c591459c3887"
f45_hex = "0269dd12fe3435ea63f63aef17f8362cdba8"

# Convert to bytes
k1 = bytes.fromhex(k1_hex)
k21 = bytes.fromhex(k21_hex)
k23 = bytes.fromhex(k23_hex)
k1234 = bytes.fromhex(k1234_hex)
f45 = bytes.fromhex(f45_hex)

# Calculate KEY4 = k1234 ^ k23 ^ k1
KEY4 = bytes(a ^ b ^ c for a, b, c in zip(k1234, k23, k1))

# Calculate FLAG ^ KEY5 = f45 ^ KEY4
flag_xor_key5 = bytes(a ^ b for a, b in zip(f45, KEY4))

# Try different known plaintext prefixes
prefixes = [b"cry{"]

for prefix in prefixes:
    KEY5 = bytes(flag_xor_key5[i] ^ prefix[i] for i in range(4))
    
    # Decode FLAG using repeating KEY5
    flag_bytes = []
    for i in range(len(flag_xor_key5)):
        flag_bytes.append(flag_xor_key5[i] ^ KEY5[i % 4])
    
    flag = bytes(flag_bytes)
    
    # Check if result is valid ASCII
    try:
        flag_str = flag.decode('ascii')
        if all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!? ' for c in flag_str):
            print(f"KEY5: {KEY5.hex()}")
            print(f"FLAG: {flag_str}")
            print()
    except:
        continue
