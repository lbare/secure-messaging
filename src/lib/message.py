import basic_crypto
import generate_hmac
from datetime import datetime


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
            username=None, password=None,
            user_id=None, recipient_id=None,
            encrypted_payload=None
    ):
        self.msg_type = msg_type
        self.msg_content = msg_content
        self.public_key = public_key
        self.private_key = private_key
        self.shared_client_key = shared_client_key
        self.shared_server_key = shared_server_key
        self.username = username
        self.password = password
        self.user_id = user_id
        self.recipient_id = recipient_id
        self.encrypted_payload = encrypted_payload

    def generate_msg(self):
        """
        Generates formatted message depending on message type

        Returns: string
        """
        match self.msg_type:
            case "message_to_server":
                return self.message_to_server()
            case "message_from_server":
                return self.message_from_server()
            case "request":
                return self.request_msg()
            case "response":
                return self.response_msg()
            case "success":
                return self.success_msg()

    def message_to_server(self):
        """
        For use with message sent from client intended for other client,
        needing to go through server first. Message in the encrypted form:
        {message_type:send_message, recipient_id:id, timestamp:timestamp, payload:
            {hmac:hmac, timestamp:timestamp, message:message}p-p-key
        }sender-server-key

        Returns: string
        """
        hmac = generate_hmac.generate_new_hmac(self.public_key, self.msg_content)

        client_payload = f"hmac:{hmac}, timestamp:{generate_timestamp()}, message:{self.msg_content}"
        encrypted_client_payload = basic_crypto.encrypt_message(client_payload, self.shared_client_key)

        server_payload = f"message_type:{self.msg_type}, recipient_id:{self.recipient_id}, " \
                         f"timestamp:{generate_timestamp()}, payload:{encrypted_client_payload}"
        encrypted_server_payload = basic_crypto.encrypt_message(server_payload, self.shared_server_key)

        return encrypted_server_payload

    def message_from_server(self):
        """
        For use with message sent from client intended for other client,
        after being sent to the server. Message in the encrypted form:
        {sender_id:id, timestamp: timestamp, payload:
            {hmac:hmac, timestamp:timestamp, message:message}p-p-key
        }recipient-server-key

        Returns: string
        """
        recipient_payload = f"sender_id:{self.user_id}, " \
                            f"timestamp:{generate_timestamp()}, " \
                            f"payload:{self.encrypted_payload}"

        return recipient_payload

    def request_msg(self):
        """
        For use with message request for initial login and sign-up,
        from client to server. Message in the unencrypted form:
        {message_type:create_account, public_key: public_key}

        Returns: string
        """
        payload = f"message_type:{self.msg_type}, public_key:{self.public_key}"

        return payload

    def response_msg(self):
        """
        For use with message after initial login and sign-up, giving user's
        credentials, from client to server. Message in the encrypted form:
        {message_type:sign_up, username:username, password:password}client-server-key

        Returns: string
        """
        payload = f"message_type:{self.msg_type}, username:{self.username}, password:{self.password}"
        encrypted_payload = basic_crypto.encrypt_message(payload, self.shared_server_key)

        return encrypted_payload

    def success_msg(self):
        """
        For use with message after successful login and sign-up,
        from server to client. Message in the encrypted form:
        {user_id:id}client-server-key

        Returns: string
        """
        payload = f"user_id:{self.user_id}"
        encrypted_payload = basic_crypto.encrypt_message(payload, self.shared_server_key)

        return encrypted_payload


if __name__ == "__main__":
    # Alice sending message intended for Bob

    # user IDs and login
    alice_id = 123
    bob_id = 456
    alice_username = "alice"
    alice_password = "password"

    # public keys
    alice_public_key = "vcxz"
    bob_public_key = "rewq"
    server_public_key = "fdsa"

    # private keys
    alice_private_key = "qwer1234"
    bob_private_key = "asdf5678"
    server_private_key = "zxcv9012"

    # generate shared keys
    alice_bob_shared_key = "uiop"
    alice_server_shared_key = "hjkl"
    bob_server_shared_key = "vbnm"

    # other message parameters
    msg_type_test = "message_to_server"
    msg_content_test = "hello there"
    sender_id_test = alice_id
    recipient_id_test = bob_id

    # tests
    sign_up_request = Message(msg_type="request", public_key=alice_public_key) \
        .generate_msg()
    sign_up_response = Message(msg_type="response", username=alice_username, password=alice_password) \
        .generate_msg()
    sign_up_success = Message(msg_type="success", user_id=alice_id) \
        .generate_msg()

    message_to_server_test = Message(msg_type="message_to_server", msg_content=msg_content_test,
                                     public_key=alice_public_key, recipient_id=recipient_id_test,
                                     shared_server_key=alice_server_shared_key)
    message_from_server_test = Message(msg_type="message_from_server", msg_content=message_to_server_test,
                                       user_id=alice_id, encrypted_payload=message_to_server_test)

    print(f"Sign Up:\n"
          f"{sign_up_request}\n"
          f"{sign_up_response}\n"
          f"{sign_up_success}\n")

    print(f"Message:\n"
          f"{message_from_server_test}\n"
          f"{message_from_server_test}\n")
