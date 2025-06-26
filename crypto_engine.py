# crypto_engine.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt_key(pub_key_bytes, aes_key):
    pub_key = RSA.import_key(pub_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def rsa_decrypt_key(priv_key_bytes, enc_key_bytes):
    priv_key = RSA.import_key(priv_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    aes_key = cipher_rsa.decrypt(enc_key_bytes)
    return aes_key

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def aes_decrypt(enc_message, key):
    iv, ct = enc_message.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')
