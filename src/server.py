import socket
import threading
import lib.db_handler as db
from lib.message import Message
from lib.message_handler import MessageHandler as mh
import lib.generate_keys as key_gen


class Server:
    """
    The Server object runs on a remote box with a public facing IP address that can be accessed by the clients
    It is in charge of signing up new users, logging in users, giving out contact information, and routing
    messages between clients
    """
    address = (socket.gethostbyname(socket.gethostname()), 9999)
    print(address)

    def __init__(self):
        # The current server-client keys associated with the users in the active session
        self.active_keys = {}
        # The current list of active users available for message routing
        self.active_users = {}
        self.server = None
        self.database = db.ServerDatabaseHandler()
        self.start_server()
        self.key_generator = key_gen.generate_new_DH()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(Server.address)
        self.server.listen()

    def handle_new_connection(self, client: socket.socket):
        """
        When a new socket connection appears, perform a DH key exchange, then wait for either a sign-up or login request
        :param client: A socket object connected to the client
        :return: None
        """
        msg = client.recv(1024)
        content = mh.get_message_contents(msg)
        # If the message isnt a login/signup request, terminate the connection
        if content["message_type"] != "request":
            client.close()
            return
        # Perform DH
        shared_key = key_gen.generate_shared_key(self.key_generator, int(content["public_key"]))
        resp_message = Message(msg_type="request", public_key=self.key_generator.gen_public_key())
        payload = resp_message.generate_msg()
        client.sendall(payload)
        try:
            self._wait_for_login(client, shared_key)
            self.handle_client(client, shared_key)
        except ConnectionResetError:
            print("Connection ended")
            return

    def _wait_for_login(self, client: socket.socket, shared_key):
        """
        Once a successful DH has been performed, wait for sign-up/login requests, when a successful login is performed, go onto the regular handler
        :param client: A socket object
        :param shared_key: The shared key between the client and server
        :return: None
        """
        data = client.recv(1024)
        while data:
            content = mh.get_message_contents(data, server_key=shared_key)
            message_type = content["message_type"]
            # If its a signup request
            if message_type == "sign-up":
                self.handle_signup_process(client, content, shared_key)
            # If its a login request
            elif message_type == "login":
                user_id = self.handle_login_process(client, content, shared_key)
                if user_id != "None":
                    # if its successful move on to the regular handler
                    self.active_keys[str(user_id)] = shared_key
                    self.active_users[str(user_id)] = client
                    return
            else:
                print(f"Invalid message type waiting for login: {message_type}")
            data = client.recv(1024)

    def handle_client(self, client: socket.socket, shared_key):
        """
        Once a client has successfully logged in, allow them to perform authenticated operations
        :param client: A socket object
        :param shared_key: A shared key between the server and client
        :return: None
        """
        data = client.recv(1024)
        timestamp = 0
        while data:
            # Decrypt message using server-client shared key
            content = mh.get_message_contents(data, server_key=shared_key)
            message_type = content["message_type"]
            # If its a message to another client, route it to the recipient
            if message_type == "message_to_server":
                timestamp = self.route_message(content, shared_key, timestamp)
            # If its a delete account request, delete the account
            elif message_type == "delete":
                self.handle_delete(client, content)
                return
            # If its a logout request, logout
            elif message_type == "logout":
                self.handle_logout(client, content)
                return
            # If its an add contact reqeust, find the relevant user_id and send it back
            elif message_type == "add-contact":
                self.handle_add_contact(client, content, shared_key)
            # If it is a client-client DH request, route the message appropriately
            elif message_type == "client_key_request":
                self.handle_client_key_request(content, shared_key)
            else:
                print(f"Invalid message type: {message_type}")
            data = client.recv(1024)

    def handle_add_contact(self, client, content, shared_key):
        """
        Given a contact username, send a user_id back to the client
        :param client: a socket object
        :param content: A dictionary containing a username
        :param shared_key: A shared server-client key
        :return: None
        """
        username = content['username']
        user_id = self.database.get_user_by_name(username)
        message = Message(msg_type="response", action="add-contact", username=username, password=user_id,
                          shared_server_key=shared_key).generate_msg()
        client.sendall(message)

    def handle_logout(self, client, content):
        """
        Handling a logout request from a client
        :param client: A socket object
        :param content: A user_id associated with the logout request
        :return: None
        """
        user_id = content['username']
        del self.active_keys[user_id]
        del self.active_users[user_id]
        client.close()

    def handle_delete(self, client, content):
        """
        Handling deletion of user account
        :param client: Socket object
        :param content: Contains the relevant user_id
        :return: None
        """
        user_id = content['username']
        try:
            del self.active_keys[user_id]
            del self.active_users[user_id]
        except KeyError:
            print(self.active_keys)
            print(self.active_users)
        client.close()
        self.database.delete_user(user_id)

    def handle_signup_process(self, client, signup_message, client_server_key):
        """
        Given a socket, username, password, and shared key create a new user account
        :param client: socket object
        :param signup_message: username and password
        :param client_server_key: shared server-client key
        :return: None
        """
        username = signup_message["username"]
        password = signup_message["password"]
        user_id = self.database.insert_new_user(username, password)
        if not user_id:
            print("Sign-up failed user already exists")
            return
        msg = Message(msg_type="success", shared_server_key=client_server_key,
                      user_id=user_id, username=username).generate_msg()
        client.sendall(msg)
        return

    def handle_login_process(self, client, login_message, client_server_key):
        """
        Given a username and password from a client handle the login request
        :param client: Socket object
        :param login_message: message containing username and password
        :param client_server_key: shared key
        :return:
        """
        username = login_message["username"]
        password = login_message["password"]
        user = self.database.login(username, password)
        if len(user) == 0:
            user_id = "None"
        else:
            user_id = user["user_id"]
        msg = Message(msg_type="success", shared_server_key=client_server_key,
                      user_id=user_id, username=username).generate_msg()
        client.sendall(msg)
        return user_id

    def route_message(self, message, client_server_key, old_timestamp):
        """
        Upon receiving a message intended for another recipient, route it to that recipient
        :param message: The message to be routed the ["payload"] value is encrypted under the client-client key and
                        is therefore unreadable to the server
        :param client_server_key: the shared server-client key from the sender
        :param old_timestamp: The timestamp of the previous message from that sender, used to prevent replay attacks
        :return: None
        """
        recipient_id = message["recipient_id"]
        timestamp = message["timestamp"]
        # Check for replay attack
        if float(timestamp) <= float(old_timestamp):
            print("Potential replay attack")
            return
        # Check if the intended recipient is available to receive a message
        if recipient_id not in self.active_keys.keys():
            print(f"No active user with that ID {recipient_id}")
            return
        recipient_server_key = self.active_keys[recipient_id]
        sender_id = [key for key, value in self.active_keys.items() if value == client_server_key][0]
        # create new message to route to the recipient
        msg = Message(msg_type="message_from_server", user_id=sender_id,
                      encrypted_payload=message["payload"], recipient_server_key=recipient_server_key).generate_msg()
        self.active_users[recipient_id].sendall(msg)
        return timestamp

    def handle_client_key_request(self, content, client_server_key):
        """
        Route a client-client DH request to the intended recipient
        :param content: The public key and id of the sender
        :param client_server_key: The sender-server key
        :return: None
        """
        recipient_id = content["id"]
        public_key = content["public_key"]
        recipient_server_key = self.active_keys[recipient_id]
        sender_id = [key for key, value in self.active_keys.items() if value == client_server_key][0]
        # Route the message to the recipient
        msg = Message(msg_type="client_key_request", recipient_id=sender_id,
                      public_key=public_key, shared_server_key=recipient_server_key).generate_msg()
        self.active_users[recipient_id].sendall(msg)



def main():
    server = Server()
    server_socket = server.server

    while 1:
        client, c_address = server_socket.accept()
        print(c_address)
        # Each time a new connection is recieved spin up a new handler thread
        client_thread = threading.Thread(target=server.handle_new_connection, args=[client], daemon=True)
        client_thread.start()


if __name__ == '__main__':
    main()
