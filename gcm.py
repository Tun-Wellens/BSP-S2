""" Module for GCM (Galois Counter Mode) mode of operation for block ciphers.
    Same as CM but with additional authentication (as a TAG)"""

from cm import nonce, increment_counter
from cbc import inverse_to_word
from encryption import encrypt, key_expansion, XOR
"""
master_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
file_path = "test_large.txt"
output_path = "test_encrypted.txt" """


def multiply(a, b):
    """Multiply two polynomials in GF(2^128)"""
    # Convert list to integer
    a = int.from_bytes(a, byteorder='big')
    b = int.from_bytes(b, byteorder='big')

    # Initialize result polynomial
    result = 0

    # Perform polynomial multiplication
    for i in range(b.bit_length()):
        if b & (1 << i):  # Check if the i-th bit is set
            result ^= (a << i)  # Shift a left by i bits and XOR with result

    # Define the irreducible polynomial for GF(2^128)
    irreducible = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | (1 << 0)

    # Reduction process
    while result.bit_length() > 128:
        for i in range(result.bit_length() - 128, -1, -1):
            if result & (1 << (i + 128)):  # Check if the bit at position i+128 is set
                result ^= irreducible << i  # Shift irreducible left by i bits and XOR with result

    # Return the result as a list of 16 bytes
    return list(result.to_bytes(16, byteorder='big'))

"""
# Example usage:
num_1 = [28, 243, 94, 212, 138, 36, 228, 236, 227, 41, 121, 50, 245, 173, 13, 43]
num_2 = [221, 85, 10, 191, 160, 251, 170, 86, 90, 7, 194, 191, 1, 169, 57, 118]

print(multiply(num_1, num_2))"""


def gcm_encrypt(master_key, file_path, output_path):

    nonce_ = nonce()

    output_file = open(output_path, "wb")
    output_file.write(bytes(nonce_))

    input_file = open(file_path, "rb")
    counter = [0, 0, 0, 0, 0, 0, 0, 0]
    encrypted_nonce = encrypt (nonce_ + counter, key_expansion(master_key))
    increment_counter(counter)
    H = inverse_to_word(encrypt([0]*16, key_expansion(master_key)))
    current_tag = [0]*16 #0 because XOR with 0 is the same
    cipher_length = 0
    while True:
        block = [byte for byte in input_file.read(16)]
        if len(block) == 0:
            break
        elif len(block) < 16:
            while len(block) < 16:
                block += b"\0"
            cipher = encrypt(nonce_ + counter, key_expansion(master_key))
            ciphertext = XOR(inverse_to_word(cipher), block)
            output_file.write(bytes(ciphertext))
            current_tag = multiply(H, XOR(ciphertext, current_tag))
        else:
            cipher = encrypt(nonce_ + counter, key_expansion(master_key))
            ciphertext = XOR(inverse_to_word(cipher), block)
            output_file.write(bytes(ciphertext))
            current_tag = multiply(H, XOR(ciphertext, current_tag)) #first itteration XOR with 0 so it stays the same
        increment_counter(counter)
        cipher_length += 128

    cipher_length = list(cipher_length.to_bytes(16, byteorder='big'))
    current_tag = multiply(H, XOR(cipher_length, current_tag))
    final_tag = XOR(inverse_to_word(encrypted_nonce), current_tag)
    output_file.write(bytes(final_tag))
    input_file.close()
    output_file.close()

#gcm_encrypt(master_key, file_path, output_path)

def gcm_decrypt(master_key, file_path, output_path):
    input_file = open(file_path, "rb")
    output_file = open(output_path, "wb")
    nonce_ = [byte for byte in input_file.read(8)] #read nonce from file
    counter = [0, 0, 0, 0, 0, 0, 0, 0]
    encrypted_nonce = encrypt(nonce_ + counter, key_expansion(master_key)) 
    increment_counter(counter)
    H = inverse_to_word(encrypt([0]*16, key_expansion(master_key)))
    input_file.seek(-16, 2) #go to the end of the file
    given_tag = [byte for byte in input_file.read(16)] #read the tag from the file
    input_file.seek(8) #go back to the start of the file(after nonce read)
    current_tag = [0]*16
    cipher_length = 0
    while True:
        block = [byte for byte in input_file.read(16)]
        if block == given_tag:
            #this means we have reached the tag (end of the file)
            break
        elif len(block) != 16:
            raise Exception("File is not a multiple of 16 bytes (corrupted file)")
        else:
            plain = encrypt(nonce_ + counter, key_expansion(master_key))
            plaintext = bytes(XOR(inverse_to_word(plain), block))
            output_file.write(plaintext)
            current_tag = multiply(H, XOR(block, current_tag))
        increment_counter(counter)
        cipher_length += 128

    cipher_length = list(cipher_length.to_bytes(16, byteorder='big'))
    current_tag = multiply(H, XOR(cipher_length, current_tag))
    final_tag = XOR(inverse_to_word(encrypted_nonce), current_tag)
    if final_tag == given_tag:
        print("TAG is correct")
    else:
        raise Exception("TAG is incorrect")
        
    input_file.close()
    output_file.close()

#gcm_decrypt(master_key, output_path, "test_decrypted.txt")