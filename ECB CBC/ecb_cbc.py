#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size


def decrypt(ciphertext: bytes) -> bytes:
    key = bytes.fromhex("2c4b295fe9ca7c02208e22d25e2875a8")
    cipher = AES.new(key, AES.MODE_ECB)

    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        print(f"ERROR: {e}")
        return -1

    return decrypted


def encrypt(plaintext: bytes) -> bytes:
    key = bytes.fromhex("2c4b295fe9ca7c02208e22d25e2875a8")
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(plaintext)
    ciphertext = iv + encrypted

    return ciphertext


def get_plaintext(ciphertext: bytes):
    """
    
    Using the ECB decryption, the first block of ciphertext is decrypted.
    The decrypted block is then XORd with the initialization vector.
    Since the only difference between ecb and cbc for the first block is the initialization vector this will give the plaintext for the first block.
    Next, if there is more ciphertext left, we call the function again using the rest of the ciphertext.
    In proceeding encryptions, the ciphertext from the previous block is used as the initialization vector.
    This means we can follow a similar procedure except using the previous cipher text as the other element of the XOR.
    This process can be repeated until the entire ciphertext is decrypted

    
    """
    encrypted = ciphertext[BLOCK_SIZE:]
    iv = ciphertext[:BLOCK_SIZE]
    decrypted = decrypt(encrypted[:BLOCK_SIZE])
    plain = bytes([x ^ y for (x, y) in zip(iv, decrypted)])
    if (len(ciphertext)>BLOCK_SIZE):
        plain += get_plaintext(ciphertext[BLOCK_SIZE:])
    return plain

if __name__ == "__main__":
    key = get_random_bytes(BLOCK_SIZE)
    plaintext = b"comp3109_3cb_5uck5_4v01d_17!!!!!"
    ciphertext = encrypt(plaintext)

    decrypted = get_plaintext(ciphertext)
    assert decrypted == plaintext
