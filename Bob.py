from base64 import b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA


def clean_rsa_keys():
    # Clear privatekey.pem
    with open("privatekey.pem", "w") as file:
        file.truncate(0)

    # Clear publickey.pem
    with open("publickey.pem", "w") as file:
        file.truncate(0)


def rsa_generate_key(num_bits):
    # Generate a new key
    key = RSA.generate(num_bits)

    # Save the private key
    private_key = key.export_key()
    with open("privatekey.pem", "wb") as file:
        file.truncate(0)
        file.write(private_key)

    # Save the public key
    public_key = key.publickey().export_key()
    with open("publickey.pem", "wb") as file:
        file.truncate(0)
        file.write(public_key)

    print("An RSA key pair has been generated!")


def get_aes_key():
    # Read the secret key
    with open("aeskey.pem", "rb") as file:
        key = file.read()

    return key


def aes_decryption():
    # Get the key and number of bytes
    key = get_aes_key()

    # Read the ciphertext and initialization vector
    with open("ctext.txt", "r") as file:
        ciphertext = b64decode(file.read())
    with open("iv.txt", "r") as file:
        iv = b64decode(file.read())

    # Decrypt and print the message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print("Message from Alice: " + unpad(cipher.decrypt(ciphertext), AES.block_size).decode())


def rsa_decryption():
    # Retrieve the private key and generate the cipher
    with open("privatekey.pem", "r") as file:
        private_key = RSA.import_key(file.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Read the ciphertext, key, nonce, and tag
    with open("ctext.txt", "rb") as file:
        enc_key, nonce, tag, ciphertext = [file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # Decrypt key
    key = cipher_rsa.decrypt(enc_key)
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)

    # Decrypt and print the message
    print("Message from Alice: " + cipher_aes.decrypt_and_verify(ciphertext, tag).decode())
    clean_rsa_keys()


while True:
    # Print Menu
    print("\nDecrypt using AES - 1")
    print("Decrypt using RSA - 2")
    print("Generate an RSA key pair - 3")
    print("Quit the program - 4")

    # Get user's choice
    choice = input("Please choose an option from the above list: ")

    # Error check
    while choice != "1" and choice != "2" and choice != "3" and choice != "4":
        choice = input("Please input an integer between 1 and 4: ")

    # Call appropriate function
    if choice == "1":
        aes_decryption()
    elif choice == "2":
        rsa_decryption()
    elif choice == "3":
        rsa_generate_key(2048)
    elif choice == "4":
        break
