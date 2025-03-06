"""
Module for CM (Counter Mode) mode of operation for block ciphers.
For both encryption and decryption.
"""

import random
from encryption import encrypt
from key import key_expansion, XOR
from cbc import inverse_to_word
"""
master_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
file_path = "test_large.txt"
output_path = "test_encrypted.txt"
"""
def nonce():
    return [random.randint(0, 255) for _ in range(8)]


def increment_counter(counter):
    #start from the end of the counter
    for i in range(len(counter)-1, -1, -1):
        #if the counter is less than 255, increment it and break
        if counter[i] < 255:
            counter[i] += 1
            break
        #if the counter is 255, set it to 0 and continue to the next byte
        else:
            counter[i] = 0
    return counter

def cm_encrypt(master_key, file_path, output_path):

    nonce_ = nonce()

    output_file = open(output_path, "wb")
    #write the nonce to the file
    output_file.write(bytes(nonce_))

    input_file = open(file_path, "rb")
    #initialize the counter to 0
    counter = [0, 0, 0, 0, 0, 0, 0, 0]
    while True:
        block = [byte for byte in input_file.read(16)]
        if len(block) == 0:
            break
        elif len(block) < 16:
            while len(block) < 16:
                block += b"\0"
            cipher = encrypt(nonce_ + counter, key_expansion(master_key))
            output_file.write(bytes(XOR(inverse_to_word(cipher), block)))
        else:
            cipher = encrypt(nonce_ + counter, key_expansion(master_key))
            output_file.write(bytes(XOR(inverse_to_word(cipher), block)))
        increment_counter(counter)
        
    input_file.close()
    output_file.close()

def cm_decrypt(master_key, file_path, output_path):
    input_file = open(file_path, "rb")
    output_file = open(output_path, "wb")
    #reads the nonce from the file
    nonce_ = [byte for byte in input_file.read(8)]
    counter = [0, 0, 0, 0, 0, 0, 0, 0]
    while True:
        block = [byte for byte in input_file.read(16)]
        if len(block) == 0:
            break
        elif len(block) < 16:
            raise Exception("Error: File is not a multiple of 16 bytes (corrupted file)")
        else:
            cipher = encrypt(nonce_ + counter, key_expansion(master_key))
            output_file.write(bytes(XOR(inverse_to_word(cipher), block)))
        increment_counter(counter)
        
    input_file.close()
    output_file.close()
"""
import time
start = time.time()
cm_encrypt(master_key, file_path, output_path)
cm_decrypt(master_key, output_path, "test_decrypted.txt")
end = time.time()
print("Time taken for CM mode of operation: ", end-start) """
