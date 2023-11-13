import socket
from aes_128_bit import encrypt

KEY = "a"
MSG = "Hello World!"
CIPHER = encrypt(MSG, KEY)

HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 1234))
s.listen(5)

while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established!")
    msg = CIPHER
    msg = f"{len(msg):<{HEADERSIZE}}" + msg
    clientsocket.send(bytes(msg, "utf-8"))

    full_msg = ""
    new_msg = True
    while True:
        msg = clientsocket.recv(16)
        if new_msg:
            print(f"server new message length: {msg[:HEADERSIZE]}")
            msglen = int(msg[:HEADERSIZE])
            new_msg = False
        full_msg += msg.decode("utf-8")
        if len(full_msg) - HEADERSIZE == msglen:
            print("Reply: " + full_msg[HEADERSIZE:])

            new_msg = True 
            full_msg = ""

            break
    break
