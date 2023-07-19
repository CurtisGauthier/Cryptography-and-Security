from hashlib import blake2b

# Challenge 2 Part 4:
# Write a python program to find the preimage of a given BLAKE2 hash value
def find_preimage(hash, student_number):
    # TODO function to find preimage of a BLAKE2 hash
    initial_value = str(student_number).encode()
    h = blake2b()
    for s in range (student_number, student_number+5000000 ):
        initial_value = str(s).encode()
        h = blake2b(initial_value).hexdigest()
        for i in range (1000):
            x = h
            h = blake2b(bytearray.fromhex(h)).hexdigest()
            if h == hash:
                print("Sid = " + str(s))
                print("iterations = " + str(i))
                print("current hash = " + h + "\n\n")
                print("preimage = " + x)
                break

    # Note: convert your initial value to bytes using str.encode()

if __name__ == "__main__":
    student_number = 101102886 #replace this with your student number  
    hash = "dd9b99ef6ee59fc66d7315571cc4f7f86f0eecc8982b903ece78c909f35b46aa669e293b6b3ef02d149a956e1b085360bd85be4cb2d7e50338b4669fddd1959a"
    find_preimage(hash,student_number)


