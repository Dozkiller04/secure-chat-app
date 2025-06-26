# 🔐 Secure Chat App with GUI (Python + AES + RSA)

A secure end-to-end encrypted chat application using Python, built with `socket`, `AES` + `RSA` encryption, and a clean `Tkinter` GUI interface for both the server and client.

---

## 🧠 Project Objective

Most chat applications don’t offer encryption by default. This project solves that by implementing:

- **AES (Advanced Encryption Standard)** for encrypting chat messages
- **RSA (Rivest–Shamir–Adleman)** for secure key exchange
- A simple, user-friendly **GUI** using Tkinter
- Real-time **client-server communication**

---

## 🛠️ Technologies Used

| Component     | Description                            |
|---------------|----------------------------------------|
| Python        | Programming Language                   |
| Socket        | Network communication                  |
| Tkinter       | GUI for chat interface (client/server) |
| PyCryptodome  | RSA + AES encryption library           |

---

## 📁 Project Structure
Secure_chat_app/
├── chat_gui.py # Client-side GUI
├── server_gui.py # Server-side GUI
├── crypto_engine.py # Handles encryption/decryption logic
├── requirements.txt # Required Python libraries
├── README.md # This documentation file


---

## 🚀 How to Run This Project

### 🔧 Step 1: Clone or Download
```bash
git clone https://github.com/YOUR_USERNAME/secure-chat-app.git
cd secure-chat-app
---
📦 Step 2: Install Required Packages
Make sure you're using Python 3.8+
Install dependencies:
  pip install -r requirements.txt
---
▶️ Step 3: Start the Server
Open a terminal window and run:
  python server_gui.py
---
You’ll see a GUI window that waits for a client to connect.

▶️ Step 4: Start the Client
In another terminal window:
  python chat_gui.py
Once connected, both server and client can send/receive encrypted messages via GUI.

🔐 Encryption Workflow
    -RSA Key Generation (2048-bit keys)
    -Server shares its public key
    -Client generates a random AES key
    -Client encrypts AES key using server's public RSA key
    -All messages are now encrypted using AES (CBC mode)
    -Messages are decrypted before display

✅ Ensures confidentiality between both ends.

---

🧪 Features
  -Encrypted Chat with AES + RSA
  -Secure Key Exchange
  -Tkinter GUI for ease of use
  -Real-time Communication
  -Clean and readable code structure

👨‍💻 Author
Soham Pramod Tayade
🎓 B.Sc. Cyber & Digital Science
📍 Pune, Maharashtra
🔒 Passionate about cybersecurity and ethical hacking
📧 [Add your email if you'd like]

📘 License
This project is for educational and demonstration purposes only. Not intended for production or commercial deployment.



