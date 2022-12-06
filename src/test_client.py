import socket
import threading
import lib.basic_crypto as basic_crypto
import lib.db_handler as db
import lib.generate_keys as key_gen
from lib.message import Message
from lib.message_handler import MessageHandler as mh

config = {}

with open('config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()


class Client:

    def __init__(self):
        self.databaseHandler = db.ClientDatabaseHandler()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_thread = threading.Thread(target=self.recv, daemon=True)

        self.key_generator = key_gen.generate_new_DH()
        self.client_server_key = None
        self.user_id = None
        self.conversation_keys = {}

        self.location = "Home Page"
        self.handlers = {
            "sign-up": self.sign_up,
            "login": self.login,
            "logout": self.logout,
            "msg": self.msg,
            "view-conversation": self.view_conversation,
            "delete-conversation": self.delete_conversation,
            "delete-account": self.delete_account
        }
        self._initialize_server_connection()
        self.start()
        self.databaseHandler.logout()

    def recv(self):
        while 1:
            message = self.socket.recv(1024)
            if not message:
                break
            self.handle_message(message)

    def start(self):
        command = input(f"{self.location} >> ")
        while command != "exit":
            self.handle_command(command)
            command = input(f"{self.location} >> ")

    def _initialize_server_connection(self):
        self.socket.connect((config["ip"], int(config["port"])))
        req_message = Message(msg_type="request", public_key=self.key_generator.gen_public_key()).generate_msg()
        self.socket.sendall(req_message)
        resp = self.socket.recv(1024)
        content = mh.get_message_contents(resp)
        self.client_server_key = key_gen.generate_shared_key(self.key_generator, int(content['public_key']))

    def handle_command(self, command):
        if not command:
            return
        command = command.split()
        method = command[0].lower()
        args = command[1:]
        try:
            self.handlers[method](args)
        except (KeyError, IndexError) as e:
            print("Invalid command")
            print(e)

    def login(self, args):
        username = args[0]
        password = args[1]
        user_id = self._remote_login(username, password)

        if user_id == 'None':
            print("Login failed at server")
            return

        result = self.databaseHandler.login(username, password)
        if not result:
            print("Login failed locally")
            return
        self.user_id = result
        print("Login successful")
        self.recv_thread.start()
        self.location = "Main Menu"

    def _remote_login(self, username, password):
        req = Message(msg_type="response", username=username, password=password,
                      action="login", shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(req)
        resp = self.socket.recv(1024)
        content = mh.get_message_contents(resp, server_key=self.client_server_key)
        message_type = content["message_type"]
        if message_type != "success":
            print(f"Bad message type {message_type}")
            return None
        user_id = content["user_id"]
        return user_id

    def sign_up(self, args):
        username = args[0]
        password = args[1]
        msg = Message(msg_type="response", username=username, password=password,
                      shared_server_key=self.client_server_key, action='sign-up').generate_msg()
        self.socket.send(msg)
        message = self.socket.recv(1024)
        content = mh.get_message_contents(message, server_key=self.client_server_key)
        message_type = content['message_type']
        if message_type == "success":
            self.handle_signup_response(content, password)

    def logout(self, args):
        self.location = "Home Page"

    def msg(self, args):
        self.location = f"Message {args[0]}"

    def view_conversation(self, args):
        contact_name = args[0]
        messages = self.databaseHandler.get_messages(contact_name)
        for m in messages:
            print(m)
        if len(messages) != 0:
            self.location = f"Message {contact_name}"

    def delete_conversation(self, args):
        contact_name = args[0]
        result = self.databaseHandler.delete_conversation(contact_name)
        if not result:
            print("Failed")
        else:
            print("Success")

    def delete_account(self, args):
        self.location = "Home Page"

    def handle_message(self, message):
        content = mh.get_message_contents(message, server_key=self.client_server_key)
        message_type = content["message_type"]
        if message_type == "client_key_request":
            self.handle_client_key_request(content)

    def handle_signup_response(self, content, password):
        user_id = content["user_id"]
        username = content["username"]
        self.databaseHandler.sign_up(username, password, user_id)
        print("Sign-up successful")

    def handle_client_key_request(self, content):
        sender_id = content['id']
        foreign_public_key = content['public_key']
        my_public_key = self.key_generator.gen_public_key()
        resp = Message(msg_type="client_key_request", recipient_id=sender_id,
                       public_key=my_public_key).generate_msg()
        self.socket.sendall(resp)
        shared_key = key_gen.generate_shared_key(self.key_generator, foreign_public_key)
        self.conversation_keys[sender_id] = shared_key


def main():
    client = Client()


if __name__ == '__main__':
    main()
