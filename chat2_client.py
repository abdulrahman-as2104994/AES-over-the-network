import socket
import sys
import errno
import threading
from aes_128_bit import encrypt, decrypt

HEADER_LENGTH = 10
HOST_IP = "127.0.0.1"
PORT = 12345
KEY = "1234567890123456"

# Choose a username
my_username = input("Choose your username: ")
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST_IP, PORT))
client_socket.setblocking(False) # This allows us to receive messages from the server
client_socket.send(username_header + username)

# Listen to server and send nickname
def receive():
    while True:
        try:
            username_header = client_socket.recv(HEADER_LENGTH)
            if not len(username_header):
                print("Connection closed by the server")
                sys.exit()
            
            username_length = int(username_header.decode('utf-8').strip())
            sender_username = client_socket.recv(username_length).decode('utf-8')

            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = decrypt(client_socket.recv(message_length).decode('utf-8'), KEY)

            print(f"\n{sender_username} > {message}")
            print(f"\n{my_username} > ", end="")
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print("Reading error", str(e))
                sys.exit()
            continue
        except Exception as e:
            print("General error", str(e))
            sys.exit()


# Send messages to server
def write():
    while True:
        message = encrypt(input(f"{my_username} > "), KEY)
        if message:
            message = message.encode('utf-8')
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)


# Run threads for listening and writing
write_thread = threading.Thread(target=write)
write_thread.start()

receive_thread = threading.Thread(target=receive)
receive_thread.start()
