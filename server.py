
import socket               
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = b"keykeykeykeykeykeykeykeykeykeyke"



def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.bind(('127.0.0.1', 8888))
    s.listen(1)
    print("listening on port 8888")
    conn,addr=s.accept()
    print(f"connection estb from port:{addr}")
    payload = conn.recv(1024)
    if len(payload) > 12:
        nonce = payload[:12]
        ciphertext = payload[12:]

        aesgcm = AESGCM(KEY)
    
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