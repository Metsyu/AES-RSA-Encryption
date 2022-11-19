from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def aes_generate_key(num_bytes):
    # Generate a random key
    key = get_random_bytes(num_bytes)

    # Save the secret key
    with open("aeskey.pem", "wb") as file:
        file.truncate(0)
        file.write(key)

    return key


def aes_encryption(user_input, num_bytes):
    # Generate key and cipher
    key = aes_generate_key(num_bytes)
    cipher = AES.new(key, AES.MODE_CBC)

    # Get user's message and encrypt it
    m = bytes(user_input, "utf-8")
    ciphertext_bytes = cipher.encrypt(pad(m, AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    ciphertext = b64encode(ciphertext_bytes).decode("utf-8")

    # Write to the files
    with open("ctext.txt", "w") as file:
        file.write(ciphertext)
    with open("iv.txt", "w") as file:
        file.write(iv)

    print("Encrypted message has been sent!")


def rsa_encryption(user_input):
    # Get user's message
    m = bytes(user_input, "utf-8")

    # Retrieve the public key and generate the cipher
    with open("publickey.pem", "r") as file:
        public_key = RSA.import_key(file.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Generate and encrypt a session key
    key = get_random_bytes(16)
    enc_key = cipher_rsa.encrypt(key)

    # Encrypt the message
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(m)
    with open("ctext.txt", "wb") as file:
        [file.write(x) for x in (enc_key, cipher_aes.nonce, tag, ciphertext)]

    print("Encrypted message has been sent!")


while True:
    # Print Menu
    print("\nEncrypt using AES - 1")
    print("Encrypt using RSA - 2")
    print("Quit the program - 3")

    # Get user's choice
    choice = input("Please choose an option from the above list: ")

    # Error check
    while choice != "1" and choice != "2" and choice != "3":
        choice = input("Please input an integer between 1 and 4: ")

    if choice == "3":
        break

    user_input = input("Please input the message you would like to send to Bob: ")

    # Call appropriate function
    if choice == "1":
        aes_encryption(user_input, 16)
    elif choice == "2":
        rsa_encryption(user_input)
