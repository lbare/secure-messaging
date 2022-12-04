import socket
import threading
import lib.db_handler as db_handler
import lib.basic_crypto as basic_crypto

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


    # Takes server db instance, user, the signup message that contains a username and password, and the client server key.
    # Adds that user into the DB and sends the response message of the user_id.
    # Does not return anything
    def handle_signup_process(self, db, user, signup_message, client_server_key):
        username = signup_message.username
        password = signup_message.password
        # Decrypt username and password
        user_id = db.insert_new_user(username, password)
        response_message = user_id.encode()

        # Encrypt response message
        encrypted_response_message = basic_crypto.encrypt_message(response_message, client_server_key)
        msg = "{message_type:response, nonce:" + encrypted_response_message[0] + ", tag:" + encrypted_response_message[1] + ", user_id:" + encrypted_response_message[2]+"}"
        self.users[user].send(msg.encode())

        return



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
