import socket               

def client():
    c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting")
    c.connect(('127.0.0.1', 8888))

    message = "Chill hai"
    c.send(message.encode('utf-8'))
    print("message sent")
    c.close()

if __name__ == "__main__":
    client()


