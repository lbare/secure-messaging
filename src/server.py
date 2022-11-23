import socket
import threading


class Server:
    address = (socket.gethostbyname(socket.gethostname()), 9999)

    def __init__(self):
        self.users = {}
        self.server = None
        self.start_server()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(Server.address)
        self.server.listen()

    def handle_client(self, client):
        data = client.recv(1024).decode()
        while data:
            data = data.split(':', 1)
            user = data[0]
            msg = data[1]
            self.users[user].send(msg.encode())
            data = client.recv(1024).decode()


def main():
    server = Server()
    server_socket = server.server

    while 1:
        client, c_address = server_socket.accept()
        print(c_address)
        user = client.recv(1024)
        server.users[user.decode()] = client
        new_thread = threading.Thread(target=server.handle_client, args=[client])
        new_thread.start()


if __name__ == '__main__':
    main()
