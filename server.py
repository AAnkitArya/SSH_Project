
import socket               




def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8888))
    s.listen(1)
    print("listening on port 8888")
    conn,addr=s.accept()
    print(f"connection estb from port:{addr}")
    raw_data = conn.recv(1024)
    plaintext_message = raw_data.decode('utf-8')
    print(f"message: {plaintext_message}")
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    run_server()