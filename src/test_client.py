import socket
import threading
import lib.basic_crypto as basic_crypto
import lib.db_handler as db

config = {}

with open('config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()


class Client:

    def __init__(self):
        self.databaseHandler = db.ClientDatabaseHandler()
       #self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       # self.recv_thread = threading.Thread(target=self.recv, daemon=True)
        #self.recv_thread.start()
        #self.socket.connect((config["ip"], int(config["port"])))
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

        self.start()
        self.databaseHandler.logout()

    def recv(self):
        while 1:
            message = self.socket.recv(1024).decode()
            if not message:
                break
            self.handle_message(message)

    def start(self):
        command = input(f"{self.location} >> ")
        while command != "exit":
            self.handle_command(command)
            command = input(f"{self.location} >> ")

    def handle_command(self, command):
        if not command:
            return
        command = command.split()
        method = command[0].lower()
        args = command[1:]
        try:
            self.handlers[method](args)
        except (KeyError, IndexError):
            print("Invalid command")

    def login(self, args):
        username = args[0]
        password = args[1]
        result = self.databaseHandler.login(username, password)
        if not result:
            print("Login failed")
            return
        self.user_id = result
        print("Login successful")
        self.location = "Main Menu"

    def sign_up(self, args):
        username = args[0]
        password = args[1]
        response_message = "{username:" + username + ", password:" + password + "}"

        # Encrypt response message
        encrypted_response_message = basic_crypto.encrypt_message(response_message, self.client_server_key)
        msg = b"{message_type:sign_up, nonce:" + encrypted_response_message[0] + b", tag:" + encrypted_response_message[
            1] + b", user_id:" + encrypted_response_message[2] + b"}"
        self.socket.send(msg)

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
        message_type = message.get_message_type()
        if message_type == "response":
            self.handle_signup_response(message)
        pass

    def handle_signup_response(self, message):
        self.user_id = message.get_user_id()
        username = message.get_username()
        password = message.get_password()
        self.databaseHandler.sign_up(username, password, self.user_id)
        self.location = "Main Menu"


def main():
    client = Client()


if __name__ == '__main__':
    main()
