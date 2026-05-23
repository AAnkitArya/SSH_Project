
import socket               
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization






def run_server():

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key=private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind(('127.0.0.1', 8888))
    s.listen(1)
    print("listening on port 8888")
    conn,addr=s.accept()
    print(f"connection estb from port:{addr}")
    conn.sendall(pem_public_key) #sendall use kiya kyonki send se kam data bhej sakte hain
    print("public key sent")
    encrypted_session_key = conn.recv(256) #pehle server bheja public key, then client multiplied its own with it and sent it back 
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"got it (Length: {len(session_key)})")


    payload = conn.recv(1024)
    if len(payload) > 12:
        nonce = payload[:12]
        ciphertext = payload[12:]

        aesgcm = AESGCM(session_key)
    
        try:
            decrypted_bytes=aesgcm.decrypt(nonce,ciphertext,None)
            message=decrypted_bytes.decode('utf-8')
            print(f"Message:{message}")
        except Exception as e:
            print("Decryption failed!")
    else:
        print(f"bad payload")
   
    conn.close()
    s.close()

if __name__ == "__main__":
    run_server()