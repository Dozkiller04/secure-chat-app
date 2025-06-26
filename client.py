import socket
import threading
from crypto_engine import *

client = socket.socket()
client.connect(('localhost', 9999))

server_pub_key = client.recv(4096)
aes_key = get_random_bytes(16)
client.send(rsa_encrypt_key(server_pub_key, aes_key))

messages = []

def receive():
    while True:
        try:
            enc_msg = client.recv(4096).decode()
            dec_msg = aes_decrypt(enc_msg, aes_key)
            print("Server:", dec_msg)
            messages.append(f"Server: {dec_msg}")
        except:
            break

threading.Thread(target=receive).start()

while True:
    msg = input("You: ")
    client.send(aes_encrypt(msg, aes_key).encode())
    messages.append(f"You: {msg}")

#this is older version.