import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def rsa(key, session_key, user_input):
    m = bytes(user_input, "utf-8")
    private_key = RSA.import_key(key.export_key())
    public_key = RSA.import_key(key.public_key().export_key())
    priv_cipher_rsa = PKCS1_OAEP.new(private_key)
    pub_cipher_rsa = PKCS1_OAEP.new(public_key)

    enc_start = time.time()
    enc_session_key = pub_cipher_rsa.encrypt(session_key)
    pub_cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = pub_cipher_aes.encrypt_and_digest(m)
    enc_end = time.time()

    dec_start = time.time()
    dec_session_key = priv_cipher_rsa.decrypt(enc_session_key)
    priv_cipher_aes = AES.new(dec_session_key, AES.MODE_EAX, pub_cipher_aes.nonce)
    priv_cipher_aes.decrypt_and_verify(ciphertext, tag)
    dec_end = time.time()

    return (enc_end - enc_start), (dec_end - dec_start)


def aes(key, user_input):
    m = bytes(user_input, "utf-8")

    enc_start = time.time()
    enc_cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = enc_cipher.encrypt(pad(m, AES.block_size))
    enc_end = time.time()

    iv = enc_cipher.iv

    dec_start = time.time()
    dec_cipher = AES.new(key, AES.MODE_CBC, iv)
    unpad(dec_cipher.decrypt(ciphertext_bytes), AES.block_size)
    dec_end = time.time()

    return (enc_end - enc_start), (dec_end - dec_start)


user_input = input("Please input a 7-byte message that you would like to test: ")

aes_key_16 = get_random_bytes(16)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = aes(aes_key_16, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--128-bit Key AES Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")

aes_key_24 = get_random_bytes(24)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = aes(aes_key_24, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--192-bit Key AES Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")

aes_key_32 = get_random_bytes(32)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = aes(aes_key_32, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--256-bit Key AES Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")

session_key = get_random_bytes(16)
rsa_key_1024 = RSA.generate(1024)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = rsa(rsa_key_1024, session_key, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--1024-bit Key RSA Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")

rsa_key_2048 = RSA.generate(2048)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = rsa(rsa_key_2048, session_key, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--2048-bit Key RSA Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")

rsa_key_4096 = RSA.generate(4096)
total_enc_time, total_dec_time = 0, 0
for i in range(100):
    enc_time, dec_time = rsa(rsa_key_4096, session_key, user_input)
    total_enc_time = total_enc_time + enc_time
    total_dec_time = total_dec_time + dec_time

print("\n--4096-bit Key RSA Performance--")
print("Encryption average elapsed duration: " + str((total_enc_time/100)*1000) + " ms")
print("Decryption average elapsed duration: " + str((total_dec_time/100)*1000) + " ms")
