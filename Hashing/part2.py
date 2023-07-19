# Challenge 2 Part 2:
# Write a Python program to determine the salt given the password and SHA256 hash value 
# The salt value is a sequence of 8 lowercase ascii characters

import string
import hashlib
from itertools import product, count

def bruteForce(hashed_Password, password, encoding):
    # Iterate on each possible salt value and check if it matches the sha256 hash provided
    # The function should return the salt value 
   for t in product(string.ascii_lowercase, repeat = 8):
       if checkSalt("".join(t), password, hashed_Password):
           return ("".join(t))
       
def checkSalt(salt, password, hashed_password):
    # simple check to see if a salt and password match a known hash
    if hashlib.sha256((password + salt).encode(encoding)).hexdigest() == hashed_password:
        return True
    else:
        return False

if __name__ == "__main__":
    encoding = 'ascii'
    password = "comp3109"
    hashed_password = "b92729d02bce1572e51a13546b3bb1b0ebf2e497af0e14966c9159e5f14459c9"
    saltValue = bruteForce(hashed_password, password, encoding)
    print(f"Salt value: {saltValue}")
    # sample values to check if you code works, checkSalt(salt, password, hashValue)
    # checkSalt("akeyqfab","comp3109","26d9ddc5d99cf19af88fa3646e75372a3d5765b24a522faab05b7a4a7a8f0036")

