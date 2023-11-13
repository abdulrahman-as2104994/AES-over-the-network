import socket
from aes_128_bit import decrypt, encrypt

KEY_EXCHANGE = "a"
KEY = ""

HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))

while True:
    clientsocket, address = s.accept()
    full_msg = ""
    new_msg = True
    while True:
        msg = s.recv(16)
        if new_msg:
            print(f"client new message length: {msg[:HEADERSIZE]}")
            msglen = int(msg[:HEADERSIZE])
            new_msg = False
        full_msg += msg.decode("utf-8")
        if len(full_msg) - HEADERSIZE == msglen:
            print("Encrypted key: " + full_msg[HEADERSIZE:])
            KEY = decrypt(full_msg[HEADERSIZE:], KEY_EXCHANGE)
            print("Decrypted key: " + KEY)
            
            msg = "Hello World!"
            msg = f"{len(msg):<{HEADERSIZE}}" + msg
            encrypted_msg = encrypt(KEY, msg)
            clientsocket.send(bytes(encrypted_msg, "utf-8"))

            new_msg = True 
            full_msg = ""
            # break
    # break

