""" 
Module for CBC mode of operation for block ciphers.
For both encryption and decryption.
"""
import random
from encryption import encrypt
from decryption import decrypt
from key import key_expansion, XOR, to_word
"""
master_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
file_path = "test_large.txt"
output_path = "test_encrypted.txt"
"""
def initialization_vector():
    """
    Generate a random initialization vector. Size 128 bits.
    """
    return [random.randint(0, 255) for _ in range(16)]

def inverse_to_word(words):
    """
    The inverse of the to_word function.
    """
    return [byte for word in words for byte in word]

fixed_read_size = 16 #128 bits

def cbc_encrypt(master_key, file_path, output_path):
    """
    Encrypt a file using the CBC mode of operation.
    """
    iv = initialization_vector()

    output_file = open(output_path, "wb")
    output_file.write(bytes(iv))

    input_file = open(file_path, "rb")
    previous_cipher = iv
    while True:
        block = [byte for byte in input_file.read(fixed_read_size)]
        if len(block) == 0:
            break
        elif len(block) < fixed_read_size:
            while len(block) < fixed_read_size:
                block += b"\0" #padding
            temp = XOR(block, previous_cipher) 
            cipher = encrypt(temp, key_expansion(master_key))
            output_file.write(bytes(inverse_to_word(cipher)))
            previous_cipher = inverse_to_word(cipher)
        else:
            temp = XOR(block, previous_cipher) 
            cipher = encrypt(temp, key_expansion(master_key))
            output_file.write(bytes(inverse_to_word(cipher)))
            previous_cipher = inverse_to_word(cipher)
        
    input_file.close()
    output_file.close()

def cbc_decrypt(master_key, file_path, output_path):
    input_file = open(file_path, "rb")
    output_file = open(output_path, "wb")

    previous_cipher = [byte for byte in input_file.read(fixed_read_size)] #first iteration is the IV
    while True:
        block = [byte for byte in input_file.read(fixed_read_size)]
        if len(block) == 0:
            break
        elif len(block) != fixed_read_size:
            raise ValueError("The file is not a multiple of 16 bytes (Corrupted File).")
        else:
            temp = decrypt(to_word(block), key_expansion(master_key))
            plain = XOR(inverse_to_word(temp), previous_cipher)
            output_file.write(bytes(plain))
            previous_cipher = block

    input_file.close()
    output_file.close()


"""import time
start = time.time()
cbc_encrypt(master_key, file_path, output_path)
cbc_decrypt(master_key, output_path, "test_decrypted.txt")
end = time.time()
print("Time taken for CBC mode of operation: ", end-start)"""