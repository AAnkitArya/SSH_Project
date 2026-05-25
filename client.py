import socket 
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

CLIENT_PRIVATE_KEY_PEM ="""-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDkWKITSjzQxDtZ
eiQI9WYvqA6pBXCbsOCCscZ3GfSOPIpoN8wODuFEheLRkaT7UeiJsyFMph+/wwFv
T8lQYH6yYCSB/+ohPjQJ7BMGauUPI0gNVCL1kOJRzq4AInQ9yRxErY/phIMV0X9v
37cBKecc3l7SqL60DphKmYTwrzn1X9Lzcj6N3wWqPzKBnVkU746pOEbPT1Rl9oI9
3e9ucalAYdqJWq/Gc0t+wIEJybO8QCQnCMNNrsKRo3Vo/cJLYzT8UFZnbY2Of/3T
/kBh0ILMf0aOK9aO5l4oNzJZoGZzI7CAVyjNJHrHZLwJb+el5hQRKUQOtZKXh7ZF
Eoxo9k2jAgMBAAECggEAazPxY30G8DwwYOGm6U3Mm7Mart+O7okr3i/4LRJSbjSe
Bi+r7S2vNKxmwFzQR+08bulaSNH1NeInWkrrCIFE+hmJCj9LfC/n3oCmreyhfWni
+d72SrOqjR2rMwT57cftLZEOb2N251djrPIqyLETf8omWmA+p+nyNZO9hgG+BCQF
fiJg5+7EvTYwA3VJV2PyAY7HFwjAb1J5P9x35TvV2czivbFijHLeEVjKmO5gMp2s
aQ7btL1rkJZHe2vYXImql4CWcHBaG7LKeEIm2fTMsSrOa0L076KaWyiYdyJV7v5K
10H0SQBTimn2M/obxx1GcXsI6Q6U34/IpGuRJpkyAQKBgQD8B2aQgcfjq/hbB8pX
Go2Nja2NHmFhXbVv2u9ZFCeHGSJqUB9xmEJOQMYimkc/4zvjD4n91lNsA3EAZ+tt
CYLD9TIxTuGMG7BKy0XljQbhmGXjIG4JuGco4yfZGb6btKQ6OuWl2+XOUIzUSBEG
BWhfYyqzZHllff42vY2XR6cVkwKBgQDn8bRbjo5Owb81yA7OwKEHDWyRLDRxkTdI
SGR4yOK8Zg9orjbZBfFEj+0XEOp7BzqT1vgCRkptvGBRchE8jzSmiNJp6cNuYLtp
uSOpRj8fwYyLlQB+ieMaIX2t62QDT7PU4I+iiPglYsMh8sHtuyyFB/mNka17qL2/
hxXAZPvxsQKBgQDNW9Zl32oaCLGIszNbgEZhVlVZDK06ohnKN/IZeoOu4Hsbd4f3
jqJQkxUfcuillSniHXJKRI6bD77PHt5FbZ+AvtWUOfssqA8hErs0jZJS1lQHGxCu
mPRt65I3o3Od+jZrQDyJxkFduGLYQpSkfFmMiAhuPmtwmJZA0nmCEB+EQwKBgQCm
XEi+eqs7dd/NlWZ5iNR2mHxMS+Z5pmx+Xd4ifAOUmadnr70LQCXixVCKgMmN4It1
SnSsPPpZZwm2oRgX1acv42b4LIDOBHenxvD7ErVn84z4+LBYElJfhbH9Mp6TeXFE
uKSNMay6M/I9wT6zYtL1v9iQX/KMhWVDoIJLcqL6oQKBgQDJ3Uu6XXZM+IkVCnof
JLIbpQF0wPNCROuJugssXrEihru9XBweExwRjpl1qF1vlB5Lq5mfKxy77rgA4mls
7/LJQAwrLW8V9S4C4SUw/VRpJQo6KeTCSXK7wGy292Sft+u8vbSVQGpvUn+gvbAX
TujZqWB7LQ5v/X5mOX9C8rlsfQ==
-----END PRIVATE KEY-----"""

client_private_key=serialization.load_pem_private_key(CLIENT_PRIVATE_KEY_PEM.encode('utf-8'), password=None)

def client():

    c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting")
    c.connect(('127.0.0.1', 8888))

    server_public_key_bytes = c.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    session_key = os.urandom(32)

    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    c.sendall(encrypted_session_key)
    
    aesgcm=AESGCM(session_key)
    challenge_data = c.recv(512)
    srv_nonce = challenge_data[:12]
    srv_ciphertext = challenge_data[12:]

    raw_challenge = aesgcm.decrypt(srv_nonce, srv_ciphertext, None)

    raw_signature = client_private_key.sign(raw_challenge,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    
    noncesig = os.urandom(12)
    en_sign = aesgcm.encrypt(noncesig, raw_signature, None)
    c.sendall(noncesig + en_sign)

    status_payload = c.recv(512)

    if not status_payload:
        print("[-] FATAL: Server dropped the connection unexpectedly. Check server logs.")
        c.close()
        return
        
    status_nonce = status_payload[:12]
    status_cipher = status_payload[12:]
    auth_status = aesgcm.decrypt(status_nonce, status_cipher, None).decode('utf-8')
    if auth_status != "AUTH_SUCCESS":
        print("disconnecting")
        c.close()
        return
    print("started...")
    print("type exit or quit to stop")

    while True:
        command = input("sshshell> ")
        if not command.strip():
            continue

        cmdnonce = os.urandom(12)
        cmdciphertext = aesgcm.encrypt(cmdnonce, command.encode('utf-8'), None)
        c.sendall(cmdnonce + cmdciphertext)

        if command.strip().lower() in ['exit', 'quit']:
            break

        # recieving it back
        respayload = c.recv(8192)
        if not respayload:
            print("connection lost")
            break
        respnonce = respayload[:12]
        respciphertext = respayload[12:]

        try:
            output = aesgcm.decrypt(respnonce, respciphertext, None).decode('utf-8')
            print(output, end="")
        except Exception as e:
            print(f"{e}")
            break

    c.close()

if __name__ == "__main__":
    client()
