
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


    

    challenge_number=os.urandom(32)
    nonce_new=os.urandom(12)
    ciphertext2=aesgcm.encrypt(nonce_new,challenge_number,None)
    to_send=nonce_new+ciphertext2
    s.sendall(to_send)


    





    s.listen(1)
    conn,addr=s.accept()
    encrypted_session_key = conn.recv(256)
    nonce2=encrypted_session_key[:12]
    cipher2=encrypted_session_key[12:]
    try:
   
        raw_signature = aesgcm.decrypt(client_nonce, signature_ciphertext, None)
    
        print("decrypted")
    except Exception as e:
        print("decryption fail!")
        conn.close()
        return
    





    try:
        client_public_key.verify(raw_signature,challenge,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    except Exception as e:
        print("couldnt verify public key")
    


    print("listening on port 8888")
    
    print(f"connection estb from port:{addr}")
    conn.sendall(pem_public_key) #sendall use kiya kyonki send se kam data bhej sakte hain
    print("public key sent")
     #pehle server bheja public key, then client multiplied its own with it and sent it back 
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