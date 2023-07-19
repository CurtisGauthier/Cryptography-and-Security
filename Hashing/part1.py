import string
import hashlib
import random

student_number = "101102886"

while(True):
    password = ''.join(random.choice(string.ascii_letters) for i in range(8))
    password_with_salt = password + student_number
    password_hash = hashlib.sha256(password_with_salt.encode()).hexdigest()
    if password_hash[0:8] == "c0ffee86": break
print("Student number: " + student_number )
print("Password hash: ☕️ " + password_hash)
print ("Password: " + password)
