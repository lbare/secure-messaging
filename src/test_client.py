import socket
import threading
import lib.basic_crypto as basic_crypto
import lib.db_handler as db
import lib.generate_keys as key_gen
from lib.message import Message
from lib.message import generate_timestamp
from lib.message_handler import MessageHandler as mh
import time

config = {}

with open('config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()


class Client:

    def __init__(self):
        self.databaseHandler = db.ClientDatabaseHandler()

        self.socket = None
        self.recv_thread = threading.Thread(target=self.recv, daemon=True)
        self.in_dH = False

        self.key_generator = key_gen.generate_new_DH()
        self.client_server_key = None
        self.user_id = None
        self.username = None
        self.conversation_keys = {}

        self.location = "Home Page"
        self.handlers = {
            "sign-up": self.sign_up,
            "login": self.login,
            "logout": self.logout,
            "msg": self.msg,
            "view-conversation": self.view_conversation,
            "delete-conversation": self.delete_conversation,
            "delete-account": self.delete_account,
            "add-contact": self.add_contact
        }
        self._initialize_server_connection()
        self.start()
        self.databaseHandler.logout()

    def recv(self):
        while True:
            try:
                message = self.socket.recv(1024)
            except ConnectionAbortedError as e:
                return
            if not message:
                break
            self.handle_message(message)

    def start(self):
        command = input(f"{self.location} >> ")
        while command != "exit":
            self.handle_command(command)
            command = input(f"{self.location} >> ")

    def _initialize_server_connection(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((config["ip"], int(config["port"])))
        req_message = Message(msg_type="request", public_key=self.key_generator.gen_public_key()).generate_msg()
        self.socket.sendall(req_message)
        resp = self.socket.recv(1024)
        content = mh.get_message_contents(resp)
        self.client_server_key = key_gen.generate_shared_key(self.key_generator, int(content['public_key']))

    def handle_command(self, command):
        if not command:
            return
        command = command.split(" ", 1)
        method = command[0].lower()
        if len(command) > 1:
            args = command[1:]
        else:
            args = []
        try:
            self.handlers[method](args)
        except (KeyError, IndexError) as e:
            print("Invalid command")
            print(e)

    def login(self, args):
        args = args[0].split()
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
        self.username = username
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
        args = args[0].split()
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
        message = Message(msg_type="response", action="logout",
                          username=self.user_id, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(message)
        self.databaseHandler.logout()
        self.recv_thread.join(0)
        self.socket.close()
        self.location = "Home Page"
        exit(0)

    def msg(self, args):
        args = args[0].split(" ", 1)
        recipient = args[0]
        content = args[1]

        recipient_id = self.databaseHandler.get_id(recipient)

        if recipient_id not in self.conversation_keys.keys():
            self._initiate_DH_exchange(recipient_id)
        message = Message(msg_type="message_to_server", recipient_id=recipient_id,
                          msg_content=content, shared_client_key=self.conversation_keys[str(recipient_id)],
                          shared_server_key=self.client_server_key).generate_msg()

        self.socket.sendall(message)

        self.databaseHandler.add_message(recipient_id, content, generate_timestamp(), self.username)
        self.location = f"Message {args[0]}"

    def _initiate_DH_exchange(self, recipient_id):
        self.in_dH = True
        my_public_key = self.key_generator.gen_public_key()
        resp = Message(msg_type="client_key_request", recipient_id=recipient_id,
                       public_key=my_public_key, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(resp)
        while self.in_dH:
            pass

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
        message = Message(msg_type="response", action="delete",
                          username=self.user_id, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(message)
        self.databaseHandler.delete_user(self.username)
        self.recv_thread.join(0)
        self.socket.close()
        self.location = "Home Page"
        exit(0)

    def add_contact(self, args):
        username = args[0]
        msg = Message(msg_type="response", action="add-contact",
                      username=username, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(msg)

    def handle_message(self, message):
        content = mh.get_message_contents(message, server_key=self.client_server_key,
                                          client_key_dict=self.conversation_keys)
        message_type = content["message_type"]
        if message_type == "client_key_request":
            self.handle_client_key_request(content)
        elif message_type == "message_from_server":
            self.handle_incoming_message(content)
        elif message_type == "add-contact":
            self.handle_add_contact_response(content)

    def handle_incoming_message(self, content):
        sender_id = content["sender_id"]
        timestamp = content["timestamp"]
        payload = content["payload"]
        message = payload.split(',', 1)[1].split(":", 1)[1][:-1]
        sender_name = self.databaseHandler.get_username(sender_id)
        self.databaseHandler.add_message(sender_id, message, timestamp, sender_name)
        print(f"{sender_name}: {message}")

    def handle_signup_response(self, content, password):
        user_id = content["user_id"]
        username = content["username"]
        self.databaseHandler.sign_up(username, password, user_id)
        print("Sign-up successful")

    def handle_client_key_request(self, content):
        sender_id = content['id']
        foreign_public_key = content['public_key']
        if self.in_dH:
            shared_key = key_gen.generate_shared_key(self.key_generator, int(foreign_public_key))
            self.conversation_keys[sender_id] = shared_key
            self.in_dH = False
            return

        my_public_key = self.key_generator.gen_public_key()
        resp = Message(msg_type="client_key_request", recipient_id=sender_id,
                       public_key=my_public_key, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(resp)
        shared_key = key_gen.generate_shared_key(self.key_generator, int(foreign_public_key))
        self.conversation_keys[sender_id] = shared_key

    def handle_add_contact_response(self, content):
        username = content['username']
        user_id = content['password']
        self.databaseHandler.add_contact(user_id, username)
        print(f"Contact added {username}")


def main():
    client = Client()


if __name__ == '__main__':
    main()
