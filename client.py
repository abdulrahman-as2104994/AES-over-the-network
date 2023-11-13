import socket
from aes_128_bit import decrypt

KEY = "a"
HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))

while True:
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
            print("Encrypted message: " + full_msg[HEADERSIZE:])
            print("Decrypted message: " + decrypt(full_msg[HEADERSIZE:], KEY))
             
            decrypted_msg = decrypt(full_msg[HEADERSIZE:], KEY)
            decrypted_msg = f"{len(decrypted_msg):<{HEADERSIZE}}" + decrypted_msg

            s.send(bytes(decrypted_msg, "utf-8"))
           
            new_msg = True 
            full_msg = ""
            break
    break

