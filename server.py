import json
import socket               
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import subprocess
import shlex

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
    
    print("listening on port 8888...")
    conn,addr=s.accept()
    conn.sendall(pem_public_key)
    
    encrypted_session_key = conn.recv(256)
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

    aesgcm = AESGCM(session_key)

    challenge_number=os.urandom(32)
    nonce_new=os.urandom(12)
    ciphertext2=aesgcm.encrypt(nonce_new,challenge_number,None)
    to_send=nonce_new+ciphertext2
    conn.sendall(to_send)

    sign_full= conn.recv(512)
    sign_nonce=sign_full[:12]
    sign_cipher=sign_full[12:]
    try:
        raw_signature = aesgcm.decrypt(sign_nonce, sign_cipher, None)
    except Exception as e:
        print("Failed to decrypt")
        conn.close()
        return

    with open("authorized_keys.json", "r") as f:
        keys_db = json.load(f)

    client_pem = keys_db["ankit"].encode('utf-8')
    client_public_key = serialization.load_pem_public_key(client_pem)

    try:
        client_public_key.verify(raw_signature,challenge_number,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        print("Verification successful")  
        success_nonce = os.urandom(12)
        encrypted_status = aesgcm.encrypt(success_nonce, b"AUTH_SUCCESS", None)
        conn.sendall(success_nonce + encrypted_status)
                                              
    except Exception as e:
        print("verification fail") 
        conn.close()
        s.close()
        return

    
    print("Waiting for command.....")
    
    while True:
        try:
            cmdpayload = conn.recv(4096)
            if not cmdpayload:
                break  #disconnect hogya

            cmdnonce = cmdpayload[:12]
            cmdciphertext = cmdpayload[12:]
            
            cmd = aesgcm.decrypt(cmdnonce, cmdciphertext, None).decode('utf-8')
            print(f"Executing: {cmd}")
            
            if cmd.lower() in ['exit', 'quit']:
                break

            
            args = shlex.split(cmd)
            result = subprocess.run(args, capture_output=True, text=True)
            
            
            outputcmd = result.stdout + result.stderr
            if not outputcmd:
                outputcmd = "\n" 
            
            
            outnonce = os.urandom(12)
            outciphertext = aesgcm.encrypt(outnonce, outputcmd.encode('utf-8'), None)
            conn.sendall(outnonce + outciphertext)
            
        except Exception as e:
            print(f"terminal cmd failed")
            break

    conn.close()
    s.close()
    print("shutting down")

if __name__ == "__main__":
    run_server()
