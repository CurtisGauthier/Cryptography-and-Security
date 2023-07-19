#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size


def ecb_penguin(key: bytes, img: bytes) -> bytes:
    """
    The ecb penguin does not take any initialization vector, which means that all blocks are encrypted independently.
    This means that when identical blocks are encrypted using the the same key, they will have the same output.
    When this is applied to the penguin, the pixels of the same colour will have the same data blocks.
    This means that they will be encrypted to the same output which will leave the penguin still recognizable

    """
    
    header = img[:53] 
    cipher = AES.new(key, AES.MODE_ECB)
    imgPad = pad(img[53:], BLOCK_SIZE)
    ciphertext = cipher.encrypt(imgPad)
    return header + ciphertext

def cbc_penguin(key: bytes, iv: bytes, img: bytes) -> bytes:
    """
    The cbc penguin does use an initilization vector and then uses the cipher to chain together the encryptions.
    This means that despite using indentical blocks, the XOR from the previous block will change it before it is encrypted.
    When this is applied to the penguin, pixels of the same colour will be XOR with the previous cipher which will eseentially make it a different colour before encrypting
    This means that the penguin will be completely unrecognizable

    """
    assert iv is not None
    
    header = img[:53]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    imgPad = pad(img[53:], BLOCK_SIZE)
    ciphertext = cipher.encrypt(imgPad)
    return header + ciphertext

if __name__ == "__main__":
    key = b"3109SaysAvoidECB"

    with open("tux.bmp", "rb") as f:
        img = f.read()

    with open("ecb_tux.bmp", "wb") as f:
        ciphertext = ecb_penguin(key, img)
        f.write(ciphertext)

    
    iv = get_random_bytes(BLOCK_SIZE)
    with open("cbc_tux.bmp", "wb") as f:
        ciphertext = cbc_penguin(key, iv, img)
        f.write(ciphertext)
