import socket
import threading

address = (socket.gethostbyname(socket.gethostname()), 9999)

users = {}

def handle_client(client):
    data = client.recv(1024).decode()
    while data:
        data = data.split(':', 1)
        user = data[0]
        msg = data[1]
        users[user].send(msg.encode())
        data = client.recv(1024).decode()


def main():

    print(socket.gethostbyname(socket.gethostname()))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(address)
    s.listen()
    while 1:
        client, c_address = s.accept()
        print(c_address)
        user = client.recv(1024)
        users[user.decode()] = client
        new_thread = threading.Thread(target=handle_client, args=[client])
        new_thread.start()






if __name__ == '__main__':
    main()
