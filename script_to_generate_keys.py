import socket 
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

client_private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
client_public=client_private.public_key()
pem_pub=client_public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
pem_priv = client_private.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()).decode('utf-8')

print(pem_priv)
print(pem_pub.replace('\n', '\\n'))