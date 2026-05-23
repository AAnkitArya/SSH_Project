import socket 
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY = b"keykeykeykeykeykeykeykeykeykeyke"  

def client():
    c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting")
    c.connect(('127.0.0.1', 8888))

    message = "Chill hai"
    bytes=message.encode('utf-8')
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, bytes, None)
    payload=nonce+ciphertext
    c.send(payload)
    print("message sent")
    c.close()

if __name__ == "__main__":
    client()


