import lib.basic_crypto as basic_crypto
from datetime import datetime
from lib.message_handler import MessageHandler


def generate_timestamp():
    """
    Generates timestamp to ensure message freshness, time since epoch in seconds

    Returns: float
    """
    epoch_time = datetime(1970, 1, 1)
    current_time = datetime.now()
    delta = current_time - epoch_time
    return delta.total_seconds()


class Message:
    """
    Handles message structure given necessary parameters
    such as message information, user keys, and user credentials.
    """

    def __init__(
            self, msg_type, msg_content=None,
            public_key=None, private_key=None,
            shared_client_key=None, shared_server_key=None,
            recipient_server_key=None,
            username=None, password=None,
            user_id=None, recipient_id=None,
            action=None,
            encrypted_payload=None
    ):
        self.msg_type = msg_type
        self.msg_content = msg_content
        self.public_key = public_key
        self.private_key = private_key
        self.shared_client_key = shared_client_key
        self.shared_server_key = shared_server_key
        self.recipient_server_key = recipient_server_key
        self.username = username
        self.password = password
        self.user_id = user_id
        self.recipient_id = recipient_id
        self.action = action
        self.encrypted_payload = encrypted_payload

    def generate_msg(self) -> bytes:
        """
        Generates formatted message depending on message type

        Returns: bytes
        """
        if self.msg_type == "message_to_server":
            return self.message_to_server()
        elif self.msg_type == "message_from_server":
            return self.message_from_server()
        elif self.msg_type == "request":
            return self.request_msg()
        elif self.msg_type == "response":
            return self.response_msg()
        elif self.msg_type == "success":
            return self.success_msg()
        elif self.msg_type == "client_key_request":
            return self.client_key_request()

    def client_key_request(self):
        """
        For exchanging client keys so they can perform DH key exchange.
        Of the form: {message_type=client_key_request, user_id=recipient_id, public_key=public_key}sender_server_key.
        Returns tuple in the form [cipher.nonce, tag, encrypted message].
        """
        payload = f"id:{self.recipient_id}, public_key:{self.public_key}"

        nonce, tag, encrypted_payload = basic_crypto.encrypt_message(str.encode(payload),
                                                                     str.encode(self.shared_server_key))

        return b"{message_type:client_key_request, nonce:" + nonce + b", tag:" + tag + b", payload:" + encrypted_payload + b"}"

    def message_to_server(self):
        """
        For use with message sent from client intended for other client,
        needing to go through server first. Message in the encrypted form:
        {message_type:message_to_server, nonce:nonce, tag:tag, payload:{message_type:send_message, recipient_id:id, timestamp:timestamp}sender-server-key}
        $$$
        {message_type:message_to_server, nonce:nonce tag:tag payload:{timestamp:timestamp, message:message}}p-p-key


        Returns: tuple in the form [cipher.nonce, tag, encrypted message],
        encrypted message is a nested tuple of the same form
        """
        client_payload = f"{{timestamp:{generate_timestamp()}, message:{self.msg_content}}}"
        nonce_1, tag_1, encrypted_client_payload = basic_crypto.encrypt_message(
            str.encode(client_payload), str.encode(self.shared_client_key)
        )

        inner_payload = b"{message_type:message_to_server, nonce:" + nonce_1 + b", tag:" + tag_1 + b", payload:" + encrypted_client_payload + b"}"

        server_payload = f"message_type:{self.msg_type}, recipient_id:{self.recipient_id}, " \
                         f"timestamp:{generate_timestamp()}"
        nonce_2, tag_2, encrypted_server_payload = basic_crypto.encrypt_message(
            str.encode(server_payload), str.encode(self.shared_server_key)
        )

        return b"{message_type:message_to_server, nonce:" + nonce_2 + b", tag:" + tag_2 + b", payload:" + encrypted_server_payload + b"}$$$" + inner_payload

    def message_from_server(self):
        """
        For use with message sent from client intended for other client,
        after being sent to the server. Message in the encrypted form:
        {nonce:nonce, tag:tag, payload:{sender_id:id, timestamp: timestamp, payload:payload}recipient-server-key}
        $$$
        {timestamp:timestamp, message:message}p-p-key


        Returns: bytes
        """
        recipient_payload = f"sender_id:{self.user_id}, " \
                            f"timestamp:{generate_timestamp()}"

        nonce, tag, encrypted_recipient_payload = basic_crypto.encrypt_message(
            str.encode(recipient_payload), str.encode(self.recipient_server_key)
        )

        return b"{message_type:message_from_server, nonce:" + nonce + b", tag:" + tag + b", payload:" + encrypted_recipient_payload + b"}$$$" + self.encrypted_payload

    def request_msg(self):
        """
        For use with message request for initial login and sign-up,
        from client to server. Message in the unencrypted form:
        {message_type:create_account, public_key: public_key}

        Returns: bytes
        """
        payload = f"message_type:{self.msg_type}, public_key:{self.public_key}"

        return payload.encode()

    def response_msg(self):
        """
        For use with message after initial login and sign-up, giving user's
        credentials, from client to server. Message in the encrypted form:
        {message_type:sign_up, username:username, password:password}client-server-key

        Returns: bytes
        """
        payload = f"message_type:{self.action}, username:{self.username}, password:{self.password}"
        nonce, tag, encrypted_payload = basic_crypto.encrypt_message(str.encode(payload),
                                                                     str.encode(self.shared_server_key))

        return b"{message_type:response, nonce:" + nonce + b", tag:" + tag + b", payload:" + encrypted_payload + b"}"

    def success_msg(self):
        """
        For use with message after successful login and sign-up,
        from server to client. Message in the encrypted form:
        {user_id:id}client-server-key

        Returns: tuple in the form [cipher.nonce, tag, encrypted message]
        """
        payload = f"user_id:{self.user_id}, username:{self.username}"
        nonce, tag, encrypted_payload = basic_crypto.encrypt_message(str.encode(payload),
                                                                     str.encode(self.shared_server_key))

        return b"{message_type:success, nonce:" + nonce + b", tag:" + tag + b", payload:" + encrypted_payload + b"}"


def tests():
    # Alice sending message intended for Bob

    # user IDs and login
    alice_id = 123
    bob_id = 456
    alice_username = "alice"
    alice_password = "password"

    # public key
    alice_public_key = "vcxzvcxzvcxzvcxz"

    # generate shared keys
    alice_bob_shared_key = "uiopuiopuiopuiop"
    alice_server_shared_key = "hjklhjklhjklhjkl"
    bob_server_shared_key = "vbnmvbnmvbnmvbnm"

    # encrypting tests
    MtS_nonce_1, MtS_tag_1, MtS_message_1 = Message(msg_type="message_to_server", msg_content="hello there",
                                                    public_key=alice_public_key, recipient_id=bob_id,
                                                    shared_server_key=alice_server_shared_key,
                                                    shared_client_key=alice_bob_shared_key) \
        .generate_msg()

    message_to_server_decrypt = basic_crypto.decrypt_message(
        MtS_nonce_1, MtS_tag_1, MtS_message_1, str.encode(alice_server_shared_key)
    ).decode()

    MtS_nonce_2, MtS_tag_2, MtS_message_2 = \
        [eval(item.strip()) for item in
         message_to_server_decrypt.split("payload:", 1)[1].strip().strip("(").strip(")").split(",", 2)]


def request_message_test():
    # Client
    alice_public_key = "vcxzvcxzvcxzvcxz"
    req_message = Message(msg_type="request", public_key=alice_public_key).generate_msg()
    payload = req_message
    # *sends payload*

    # Server *receives payload*
    contents = MessageHandler.get_message_contents(payload)
    print("Request Message Values")
    print(contents)


def response_message_test():
    alice_username = "alice"
    alice_password = "password"
    alice_server_shared_key = "hjklhjklhjklhjkl"

    # Client
    payload = Message(msg_type="response", username=alice_username, password=alice_password,
                      shared_server_key=alice_server_shared_key, action='sign-up').generate_msg()
    # *sends payload*

    # Server *receives payload*
    contents = MessageHandler.get_message_contents(payload, server_key=alice_server_shared_key)
    print("Response Message Values:")
    print(contents)


def client_message_test():
    alice_id = "alice"
    bob_id = "bob"
    alice_bob_key = "asdfasdfasdfasdf"
    bob_server_shared_key = "zxcvzxcvzxcvzxcv"
    alice_server_shared_key = "hjklhjklhjklhjkl"

    # *client 1 generates payload*
    payload1 = Message(msg_type="message_to_server", recipient_id=bob_id, msg_content="what's up big dog",
                       shared_client_key=alice_bob_key, shared_server_key=alice_server_shared_key) \
        .generate_msg()

    # *client 1 sends payload to server*

    # *server receives payload*
    contents1 = MessageHandler.get_message_contents(payload1, server_key=alice_server_shared_key)
    print(contents1)

    # *server sends payload to client 2*
    payload2 = Message(msg_type="message_from_server", user_id=alice_id, encrypted_payload=contents1["payload"],
                       shared_client_key=alice_bob_key, recipient_server_key=bob_server_shared_key) \
        .generate_msg()

    # *client 2 receives payload*
    contents2 = MessageHandler.get_message_contents(payload2, server_key=bob_server_shared_key,
                                                    client_key=alice_bob_key)
    print(contents2)


def success_message_test():
    alice_server_shared_key = "hjklhjklhjklhjkl"

    # Server creates message
    payload = Message(msg_type="success", shared_server_key=alice_server_shared_key, user_id='alice').generate_msg()
    # *sends payload*

    # Client *receives payload*
    contents = MessageHandler.get_message_contents(payload, server_key=alice_server_shared_key)
    print("Success Message Values")
    print(contents)


def client_key_request_test():
    alice_public_key = "vcxzvcxzvcxzvcxz"
    bob_id = "bob"
    alice_server_shared_key = "hjklhjklhjklhjkl"

    # Client
    payload = Message(msg_type="client_key_request", recipient_id=bob_id, public_key=alice_public_key,
                      shared_server_key=alice_server_shared_key).generate_msg()
    # *sends payload*

    # Server *receives payload*
    contents = MessageHandler.get_message_contents(payload, server_key=alice_server_shared_key)
    print("Client Key Request Message Values:")
    print(contents)


if __name__ == "__main__":
    # tests()
    # request_message_test()
    # print()
    # response_message_test()
    # client_message_test()
    # success_message_test()
    client_key_request_test()
