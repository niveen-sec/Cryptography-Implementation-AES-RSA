from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


# Generate RSA Keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

print("RSA Keys Generated\n")

# Choose text or file
choice = input("Enter 't' for text or 'f' for file: ")

if choice == 't':
    plaintext = input("Enter your plaintext: ").encode()
else:
    file_name = input("Enter file name: ")
    with open(file_name, 'r') as file:
        plaintext = file.read().encode()

print("\nPlain Text:")
print(plaintext.decode())


# Generate AES Key and IV
aes_key = os.urandom(32)
iv = os.urandom(16)

print("\nAES Key:")
print(base64.b64encode(aes_key).decode())


# Encrypt using AES
cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CFB(iv),
    backend=default_backend()
)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
ciphertext_base64 = base64.b64encode(ciphertext)

print("\nEncrypted Text (AES Base64):")
print(ciphertext_base64.decode())


# Encrypt AES key using RSA
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key)

print("\nEncrypted AES Key (RSA Base64):")
print(encrypted_aes_key_base64.decode())


# Decryption Option
decrypt_choice = input("\nDo you want to decrypt the text? (y/n): ").lower()

if decrypt_choice == 'y':

    # Decrypt AES key
    decrypted_aes_key = private_key.decrypt(
        base64.b64decode(encrypted_aes_key_base64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nDecrypted AES Key:")
    print(base64.b64encode(decrypted_aes_key).decode())

    # Decrypt ciphertext
    cipher_dec = Cipher(
        algorithms.AES(decrypted_aes_key),
        modes.CFB(iv),
        backend=default_backend()
    )

    decryptor = cipher_dec.decryptor()
    decrypted_text = decryptor.update(
        base64.b64decode(ciphertext_base64)
    ) + decryptor.finalize()

    print("\nDecrypted Text:")
    print(decrypted_text.decode())

else:
    print("\nDecryption skipped.")
