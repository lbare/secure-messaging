import socket
import threading
import lib.db_handler as db
import lib.generate_keys as key_gen
from lib.message import Message
from lib.message import generate_timestamp
from lib.message_handler import MessageHandler as mh

# the configuration file is used to connect to the server, it contains the port and public ip
config = {}

with open('config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()


class Client:
    """
    The Client class is in charge of running the UI, connecting to the server, and handling the sending/receiving of
    various messages to and from the server and to other clients via the server
    """

    def __init__(self):
        # A database handler object that handles interactions with the local database
        self.databaseHandler = db.ClientDatabaseHandler()

        # The socket used to connect to the server
        self.socket = None
        # The thread used to read messages coming from the server
        self.recv_thread = threading.Thread(target=self.recv, daemon=True)
        # A flag to determine whether or not the client is in a Diffie-Hellman algorithm execution
        self.in_dH = False

        # A generator used to create public/shared keys using Diffie-Hellman
        self.key_generator = key_gen.generate_new_DH()
        # The shared key between the server and the client
        self.client_server_key = None
        # The user id associated with the current session
        self.user_id = None
        # The username associated with the current session
        self.username = None
        # A dictionary of keys used to encrypt client-client communication, a different one for each contact
        self.conversation_keys = {}

        # The UI displayed location
        self.location = "Home Page"
        # A dict of commands that the UI can process along with their respective handlers
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
        # Starting the connection to the server
        self._initialize_server_connection()
        # Starting the UI
        self.start()
        # Once the session has ended the database should be closed to ensure data integrity
        self.databaseHandler.logout()

    def recv(self):
        """
        A method to be run on a thread and constantly monitor the socket for input, then forward the input to the relevant
        handler
        :return: None
        """
        while True:
            try:
                message = self.socket.recv(1024)
            except ConnectionAbortedError as e:
                return
            if not message:
                break
            self.handle_message(message)

    def start(self):
        """
        The main UI function that handles the input of commands
        Runs on the main thread
        :return: None
        """
        command = input(f"{self.location} >> ")
        while command != "exit":
            self.handle_command(command)
            command = input(f"{self.location} >> ")

    def _initialize_server_connection(self):
        """
        Initializes the connection to the server on startup, performs a DH key exchange each session to be used to encrypt
        traffic to and from the server
        :return: None
        """
        # Create the socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect it to the server using the data gained from config-file.txt
        self.socket.connect((config["ip"], int(config["port"])))
        # Create a new session request message. This message begins a DH key exchange with the server by sending a public key
        req_message = Message(msg_type="request", public_key=self.key_generator.gen_public_key()).generate_msg()
        self.socket.sendall(req_message)
        # Wait for a response
        resp = self.socket.recv(1024)
        # Parse the content of the message
        content = mh.get_message_contents(resp)
        # Generate a shared key from the servers public key
        self.client_server_key = key_gen.generate_shared_key(self.key_generator, int(content['public_key']))

    def handle_command(self, command):
        """
        Given a command from the UI, parse the command into command and args, then handle the command appropriately
        :param command: A command in the format of <command> <arg> <arg> ...
        :return:
        """
        if not command:
            return
        # Limit to single split to get [command, args]
        command = command.split(" ", 1)
        # check command input
        method = command[0].lower()
        if len(command) > 1:
            args = command[1:]
        else:
            args = []
        try:
            # handle the command using the command dictionary with the args in a single string
            self.handlers[method](args)
        except (KeyError, IndexError) as e:
            print("Invalid command")
            print(e)

    def login(self, args):
        """
        Given a username and password, login on both the server and locally
        :param args: ["username password"] format
        :return:
        """
        # Parse args
        args = args[0].split()
        username = args[0]
        password = args[1]
        # Attempt to login on the remote server, on a success obtain a valid user_id
        user_id = self._remote_login(username, password)

        if user_id == 'None':
            print("Login failed at server")
            return

        # Attempt to login to local database, on a success obtain a valid user_id
        result = self.databaseHandler.login(username, password)
        if not result:
            print("Login failed locally")
            return
        self.user_id = result
        self.username = username
        print("Login successful")
        # Once login is complete begin listening for arbitrary messages from server
        self.recv_thread.start()
        self.location = "Main Menu"

    def _remote_login(self, username, password):
        """
        Given a username and password, encrypt them and send them to the server to be processed and checked
        :param username: Username in string
        :param password: Password in string
        :return: either a valid user ID or "None"
        """
        # Create a login message with the username and password, encrypt it and send to server
        req = Message(msg_type="response", username=username, password=password,
                      action="login", shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(req)
        # Wait for response
        resp = self.socket.recv(1024)
        content = mh.get_message_contents(resp, server_key=self.client_server_key)
        # Parse contents
        message_type = content["message_type"]
        if message_type != "success":
            print(f"Bad message type {message_type}")
            return None
        # If the remote login worked will get a valid user_id, otherwise will get "None"
        user_id = content["user_id"]
        return user_id

    def sign_up(self, args):
        """
        Given a username and password, create a new user account both on the server and locally
        :param args: ["username password"]
        :return: None
        """
        args = args[0].split()
        username = args[0]
        password = args[1]
        # Create sign-up request, encrypt it and send to server
        msg = Message(msg_type="response", username=username, password=password,
                      shared_server_key=self.client_server_key, action='sign-up').generate_msg()
        self.socket.send(msg)
        # Wait for response
        message = self.socket.recv(1024)
        content = mh.get_message_contents(message, server_key=self.client_server_key)
        message_type = content['message_type']
        if message_type == "success":
            # If successfully created account remotely, create one locally
            self.handle_signup_response(content, password)

    def logout(self, args):
        """
        Logout of the remote and local services, shutdown the system
        :param args: None only included for argument symmetry
        :return: None
        """
        # Encrypt and send logout message
        message = Message(msg_type="response", action="logout",
                          username=self.user_id, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(message)
        # Close database
        self.databaseHandler.logout()
        # End recv thread
        self.recv_thread.join(0)
        self.socket.close()
        self.location = "Home Page"
        exit(0)

    def msg(self, args):
        """
        Given a username and a message, encrypt and send the message to the user using end2end encryption
        :param args: ["username message"]
        :return: None
        """
        args = args[0].split(" ", 1)
        recipient = args[0]
        content = args[1]

        # determine the user ID of the recipient from their username
        recipient_id = self.databaseHandler.get_id(recipient)

        # If a session key has not yet been established, establish one
        if recipient_id not in self.conversation_keys.keys():
            self._initiate_DH_exchange(recipient_id)
        # Once key exists create the actual message, encrypt and send it
        message = Message(msg_type="message_to_server", recipient_id=recipient_id,
                          msg_content=content, shared_client_key=self.conversation_keys[str(recipient_id)],
                          shared_server_key=self.client_server_key).generate_msg()

        self.socket.sendall(message)

        # Add the message to the local database encrypted
        self.databaseHandler.add_message(recipient_id, content, generate_timestamp(), self.username)
        self.location = f"Message {args[0]}"

    def _initiate_DH_exchange(self, recipient_id):
        """
        Given a recipient id go through a DH key exchange with the other client to establish a shared key
        :param recipient_id: The id of the intended recipient in string form
        :return: None
        """
        # Set DH flag to True
        self.in_dH = True
        # Perform DH
        my_public_key = self.key_generator.gen_public_key()
        resp = Message(msg_type="client_key_request", recipient_id=recipient_id,
                       public_key=my_public_key, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(resp)
        # Wait until a response is received
        while self.in_dH:
            pass

    def view_conversation(self, args):
        """
        Given a username display all messages to/from that user in order
        :param args: ["username"]
        :return: None
        """
        contact_name = args[0]
        messages = self.databaseHandler.get_messages(contact_name)
        for m in messages:
            print(m)
        if len(messages) != 0:
            self.location = f"Message {contact_name}"

    def delete_conversation(self, args):
        """
        Given a username, delete the conversation history with that user locally
        :param args: ["username"]
        :return: None
        """
        contact_name = args[0]
        result = self.databaseHandler.delete_conversation(contact_name)
        if not result:
            print("Failed")
        else:
            print("Success")

    def delete_account(self, args):
        """
        Given a logged in account, delete the account both remotely and locally and end the session
        :param args: None
        :return: None
        """
        # Encrypt and send the delete message to the server
        message = Message(msg_type="response", action="delete",
                          username=self.user_id, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(message)
        # Delete the user locally
        self.databaseHandler.delete_user(self.username)
        self.recv_thread.join(0)
        self.socket.close()
        self.location = "Home Page"
        exit(0)

    def add_contact(self, args):
        """
        Given a username, add that user as a contact in the local database, allowing them to be contacted later on
        :param args: ["username"]
        :return: None
        """
        username = args[0]
        # Create an add contact request to the server, the server will respond with the user_id associated with the
        # given username, this is handled in handle_add_contact_response()
        msg = Message(msg_type="response", action="add-contact",
                      username=username, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(msg)

    def handle_message(self, message):
        """
        Given a message, parse the contents and handle the relevant actions
        :param message: Bytes received from the server
        :return: None
        """
        # Decrypt and parse the bytes
        content = mh.get_message_contents(message, server_key=self.client_server_key,
                                          client_key_dict=self.conversation_keys)
        message_type = content["message_type"]
        # If it is a DH request from a client
        if message_type == "client_key_request":
            self.handle_client_key_request(content)
        # if it is a message from another client
        elif message_type == "message_from_server":
            self.handle_incoming_message(content)
        # if it is a response to an add-contact request from the server
        elif message_type == "add-contact":
            self.handle_add_contact_response(content)

    def handle_incoming_message(self, content):
        """
        This is called when a message is received from another client, i.e. a normal chat
        :param content: A dictionary containing the sender_id, the timestamp, and the message payload
        :return: None
        """
        # Pares contents
        sender_id = content["sender_id"]
        timestamp = content["timestamp"]
        payload = content["payload"]
        message = payload.split(',', 1)[1].split(":", 1)[1][:-1]
        sender_name = self.databaseHandler.get_username(sender_id)
        # Add message to database
        self.databaseHandler.add_message(sender_id, message, timestamp, sender_name)
        # Display message
        print(f"{sender_name}: {message}")

    def handle_signup_response(self, content, password):
        """
        This is called when a sign-up request is responded to by the server
        :param content: The message content containing the user_id and username of the new account
        :param password: The password associated with the account
        :return: None
        """

        user_id = content["user_id"]
        username = content["username"]
        # Add the user locally
        self.databaseHandler.sign_up(username, password, user_id)
        print("Sign-up successful")

    def handle_client_key_request(self, content):
        """
        Called upon reception of a DH request from another client
        :param content: Conatins the id of the sender and their public key
        :return: None
        """
        sender_id = content['id']
        foreign_public_key = content['public_key']
        # Check if this is the response to a DH we sent, if so create the key and terminate
        if self.in_dH:
            shared_key = key_gen.generate_shared_key(self.key_generator, int(foreign_public_key))
            self.conversation_keys[sender_id] = shared_key
            self.in_dH = False
            return

        # Otherwise create the shared key, then send our public key in response
        my_public_key = self.key_generator.gen_public_key()
        resp = Message(msg_type="client_key_request", recipient_id=sender_id,
                       public_key=my_public_key, shared_server_key=self.client_server_key).generate_msg()
        self.socket.sendall(resp)
        shared_key = key_gen.generate_shared_key(self.key_generator, int(foreign_public_key))
        self.conversation_keys[sender_id] = shared_key

    def handle_add_contact_response(self, content):
        """
        Called upon receiving response from the server from an add-contact request
        :param content: contains the username and user_id of the new contact
        :return:
        """
        username = content['username']
        user_id = content['password']
        # Add the contact to the local database
        self.databaseHandler.add_contact(user_id, username)
        print(f"Contact added {username}")


def main():
    client = Client()


if __name__ == '__main__':
    main()
