First of all I implemented a basic connection for data transfer on Tcp using socket library. 
Here I first initiated the socket and created the socket object 's', binded it to the port 8888 on localhost and tranferred basic unencrypted binary data and then decoded it using utf-8 protocol and printed it.
There was a problem with the port being busy and then got into TIMEWAIT and i implemented a standard line to free it.
Also i wrote a check so that the whole function runs only when it is called and not when the python file is imported into some other file.



In phase 2 as specified I hardcoded the keys into the file, the aesgcm encryption object was initialized on both the server and the client using the key, nonce encryption was also used in this phase. 

In phase 3 , it first recieves the public key from the server and then makes it a python object using the oad_pem_public_key function from the serialization library, it then signs it with the generated session kay of 32 bytess and sends it back, then that is decrypted on the servevr side and server gets the clients session key by using its private key.

In this phase we didnt verify the client but we established a encrypted tunnel without any hardcoded keys.

In phase 4, the client generates its own RSA keypair, and the client's public key is appended to the server's authorized_keys.json file ahead of time. Once the encrypted tunnel is fully established using the session key from Phase 3, the server generates a random 32-byte challenge string and transmits it over to the client. The client takes this challenge
and signs it using its private key with the RSA-PSS padding scheme. The server then reads the client's public key stored inside authorized_keys.json and verifies this signature against the challenge. If the signature matches, access is granted; otherwise, the connection is immediately dropped.  In phase 5, I implemented the final interactive remote shell loop.
Once the client successfully authenticates, the client terminal enters a loop to accept user commands continuously. When a command like ls, pwd, or whoami is typed, the client encrypts the string using AES-GCM with the shared session key and sends it over the socket. The server decrypts the command, executes it locally using the subprocess module from the Python
standard library, captures the standard output or standard error, encrypts that output payload, and sends it back to the client to be decrypted and printed on the screen.
