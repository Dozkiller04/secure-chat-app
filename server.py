import socket
import threading
from crypto_engine import *

server = socket.socket()
server.bind(('0.0.0.0', 9999))
server.listen(1)

private_key, public_key = generate_rsa_keys()
print("[*] Waiting for connection...")
client, addr = server.accept()
print(f"[*] Connected with {addr}")

client.send(public_key)
aes_key = rsa_decrypt_key(private_key, client.recv(4096))

def receive():
    while True:
        try:
            enc_msg = client.recv(4096).decode()
            dec_msg = aes_decrypt(enc_msg, aes_key)
            print("Client:", dec_msg)
        except:
            break

threading.Thread(target=receive).start()

while True:
    msg = input("You: ")
    client.send(aes_encrypt(msg, aes_key).encode())



#this is older version of project