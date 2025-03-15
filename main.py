"""Main module for the project. Is used for the CLI (Command Line Interface) of the project."""

from cbc import cbc_encrypt, cbc_decrypt
from cm import cm_encrypt, cm_decrypt
from gcm import gcm_encrypt, gcm_decrypt
import hashlib

def gen_key(password):
    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
    
    # Take the first 16 bytes (128 bits) of the hashed password as the key
    key = hashed_password[:16]
    return list(key)

master_key = gen_key(input("Enter the password: "))

while True:
    print("Welcome to AES encryption/decryption!")
    print("Please select an option:")
    print("1. Encrypt using CBC mode of operation")
    print("2. Decrypt using CBC mode of operation")
    print("3. Encrypt using CM mode of operation")
    print("4. Decrypt using CM mode of operation")
    print("5. Encrypt using GCM mode of operation")
    print("6. Decrypt using GCM mode of operation")
    print("7. Exit")
    option = input("Enter your option: ")
    try:
        if option == "1":
            file_path = input("Enter the path of the file you want to encrypt: ")
            output_path = input("Enter the path of the output file: ")
            cbc_encrypt(master_key, file_path, output_path)
            print("File encrypted successfully!")
        elif option == "2":
            file_path = input("Enter the path of the file you want to decrypt: ")
            output_path = input("Enter the path of the output file: ")
            cbc_decrypt(master_key, file_path, output_path)
            print("File decrypted successfully!")
        elif option == "3":
            file_path = input("Enter the path of the file you want to encrypt: ")
            output_path = input("Enter the path of the output file: ")
            cm_encrypt(master_key, file_path, output_path)
            print("File encrypted successfully!")
        elif option == "4":
            file_path = input("Enter the path of the file you want to decrypt: ")
            output_path = input("Enter the path of the output file: ")
            cm_decrypt(master_key, file_path, output_path)
            print("File decrypted successfully!")
        elif option == "5":
            file_path = input("Enter the path of the file you want to encrypt: ")
            output_path = input("Enter the path of the output file: ")
            gcm_encrypt(master_key, file_path, output_path)
            print("File encrypted successfully!")
        elif option == "6":
            file_path = input("Enter the path of the file you want to decrypt: ")
            output_path = input("Enter the path of the output file: ")
            gcm_decrypt(master_key, file_path, output_path)
            print("File decrypted successfully!")
        elif option == "7":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")
    except FileNotFoundError:
        print("File not found, please try again.")
        continue
    except Exception as e:
        print("Unexpected error occurred:", e, "\nPlease try again.")
        continue
