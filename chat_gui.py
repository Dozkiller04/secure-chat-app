import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from Crypto.Random import get_random_bytes
from crypto_engine import rsa_encrypt_key, aes_encrypt, aes_decrypt

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 9999))

server_pub_key = client.recv(4096)
aes_key = get_random_bytes(16)
client.send(rsa_encrypt_key(server_pub_key, aes_key))

# GUI Setup
window = tk.Tk()
window.title("Secure Client Chat")
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
    try:
        client.send(enc_msg.encode())
        chat_area.config(state='normal')
        chat_area.insert(tk.END, f"You: {msg}\n")
        chat_area.config(state='disabled')
        entry.delete(0, tk.END)
    except:
        chat_area.insert(tk.END, "⚠️ Failed to send message. Server disconnected.\n")

send_btn = tk.Button(window, text="Send", command=send_message)
send_btn.pack(side=tk.RIGHT, padx=(0, 10), pady=(0, 10))

def receive_messages():
    while True:
        try:
            enc_data = client.recv(4096)
            if not enc_data:
                break
            decrypted = aes_decrypt(enc_data.decode(), aes_key)
            chat_area.config(state='normal')
            chat_area.insert(tk.END, f"Server: {decrypted}\n")
            chat_area.config(state='disabled')
        except:
            break

threading.Thread(target=receive_messages, daemon=True).start()
window.mainloop()
