import socket 
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


 

def client():
    c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting")
    c.connect(('127.0.0.1', 8888))



    server_public_key_bytes = c.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes) #bytes to object

    session_key = os.urandom(32) #random 32 bytes

    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    c.sendall(encrypted_session_key)   #send the key after mixing it with public key received from server




    message = "Chill hai boss"

    aesgcm=AESGCM(session_key)  #khud key key se encrypt ye karega
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None) #aesgcm object already has the session key from the last line. nonce and session key both will be used to encrypt it, nonce for uniquiness so that hacker cannot and see if there are identical packets.
    c.sendall(nonce+ciphertext)
    print("message sent")
    c.close()



    
if __name__ == "__main__":
    client()


