import socket, threading, sqlite3, uuid


class Server:
    address = (socket.gethostbyname(socket.gethostname()), 9999)

    def __init__(self):
        self.users = {}
        self.database = None
        self.initialize_database()
        self.server = None
        self.start_server()

    def initialize_database(self):
        self.database = sqlite3.connect('credentials.db')
        self.database.execute('''CREATE TABLE IF NOT EXISTS users(
        ID INT PRIMARY KEY,
        USERNAME TEXT,
        KEY TEXT) ''')

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(Server.address)
        self.server.listen()

    def insert_new_user(self, username, key):
        user_id = uuid.uuid4().int % 1000_0000_0000_0000
        self.database.execute('''INSERT INTO users(ID, USERNAME, KEY)
                VALUES(?,?,?)''', (user_id, username, key))
        self.database.commit()
        return user_id

    def get_user(self, user_id, username, key):
        user = self.database.execute('''SELECT * FROM users 
            WHERE ID = ? AND USERNAME = ? AND KEY = ?''', (user_id, username, key))
        return user

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
