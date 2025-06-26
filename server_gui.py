# server_gui.py

import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from crypto_engine import generate_rsa_keys, rsa_decrypt_key, aes_decrypt, aes_encrypt

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Setup socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 9999))
server.listen(1)
print("[*] Waiting for client to connect...")

client, addr = server.accept()
print(f"[*] Connected with {addr}")

# Send public RSA key to client
client.send(public_key)

# Receive and decrypt AES key
aes_key = rsa_decrypt_key(private_key, client.recv(4096))

# ---------- GUI Setup ---------- #
window = tk.Tk()
window.title("Secure Server Chat")
window.geometry("500x400")

chat_area = scrolledtext.ScrolledText(window, wrap=tk.WORD)
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
chat_area.config(state='disabled')

entry = tk.Entry(window, width=60)
entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))

def send_message():
    msg = entry.get()
    if msg.strip() == "":
        return
    enc_msg = aes_encrypt(msg, aes_key)
    client.send(enc_msg.encode())
    chat_area.config(state='normal')
    chat_area.insert(tk.END, f"You: {msg}\n")
    chat_area.config(state='disabled')
    entry.delete(0, tk.END)

send_btn = tk.Button(window, text="Send", command=send_message)
send_btn.pack(side=tk.RIGHT, padx=(0, 10), pady=(0, 10))

# ---------- Background Receiver Thread ---------- #
def receive_messages():
    while True:
        try:
            enc_data = client.recv(4096)
            if not enc_data:
                break
            decrypted = aes_decrypt(enc_data.decode(), aes_key)
            chat_area.config(state='normal')
            chat_area.insert(tk.END, f"Client: {decrypted}\n")
            chat_area.config(state='disabled')
        except:
            break

threading.Thread(target=receive_messages, daemon=True).start()

window.mainloop()
