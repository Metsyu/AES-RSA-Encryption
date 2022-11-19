# AES-RSA-Encryption
A program, developed in Python, that implements AES and RSA encryption.

This program allows you to encrypt and send messages between 2 programs, Alice.py and Bob.py, using either AES or RSA.
TestPerformance.py also allows you to test the performance of each algorithm, outputted in ms.

Before sending messages, both Alice.py and Bob.py should be running.

To use AES:
  Choose 1 from Alice's menu.
  Input the message you would like to send to Bob. The message will then be encrypted and sent to Bob.
  Choose 1 from Bob's menu. The message will then be decrypted and print out.

To use RSA:
  Choose 3 from Bob's menu. An RSA key pair will then be generated.
  Choose 2 from Alice's menu.
  Input the message you would like to send to Bob. The message will then be encrypted and sent to Bob.
  Choose 2 from Bob's menu. The message will then be decrypted and print out. 
  
  Note: The key pair will be deleted after RSA decryption, a new key pair will need to be generated to utilize RSA again.
