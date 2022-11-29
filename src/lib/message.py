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
            recipient_server_key=None,
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
        self.recipient_server_key = recipient_server_key
        self.username = username
        self.password = password
        self.user_id = user_id
        self.recipient_id = recipient_id
        self.encrypted_payload = encrypted_payload

    def generate_msg(self) -> tuple:
        """
        Generates formatted message depending on message type

        Returns: tuple in the form [cipher.nonce, tag, encrypted message]
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

        Returns: tuple in the form [cipher.nonce, tag, encrypted message],
        encrypted message is a nested tuple of the same form
        """
        hmac = generate_hmac.generate_new_hmac(self.shared_client_key, self.msg_content)

        client_payload = f"hmac:{hmac}, timestamp:{generate_timestamp()}, message:{self.msg_content}"
        encrypted_client_payload = basic_crypto.encrypt_message(
            str.encode(client_payload), str.encode(self.shared_client_key)
        )

        server_payload = f"message_type:{self.msg_type}, recipient_id:{self.recipient_id}, " \
                         f"timestamp:{generate_timestamp()}, payload:{encrypted_client_payload}"
        encrypted_server_payload = basic_crypto.encrypt_message(
            str.encode(server_payload), str.encode(self.shared_server_key)
        )

        return encrypted_server_payload

    def message_from_server(self):
        """
        For use with message sent from client intended for other client,
        after being sent to the server. Message in the encrypted form:
        {sender_id:id, timestamp: timestamp, payload:
            {hmac:hmac, timestamp:timestamp, message:message}p-p-key
        }recipient-server-key

        Returns: tuple in the form [cipher.nonce, tag, encrypted message]
        """
        recipient_payload = f"sender_id:{self.user_id}, " \
                            f"timestamp:{generate_timestamp()}, " \
                            f"payload:{self.encrypted_payload}"
        encrypted_recipient_payload = basic_crypto.encrypt_message(
            str.encode(recipient_payload), str.encode(self.recipient_server_key)
        )

        return encrypted_recipient_payload

    def request_msg(self):
        """
        For use with message request for initial login and sign-up,
        from client to server. Message in the unencrypted form:
        {message_type:create_account, public_key: public_key}

        Returns: string
        """
        payload = f"message_type:{self.msg_type}, public_key:{self.public_key}"

        return None, None, payload

    def response_msg(self):
        """
        For use with message after initial login and sign-up, giving user's
        credentials, from client to server. Message in the encrypted form:
        {message_type:sign_up, username:username, password:password}client-server-key

        Returns: tuple in the form [cipher.nonce, tag, encrypted message]
        """
        payload = f"message_type:{self.msg_type}, username:{self.username}, password:{self.password}"
        encrypted_payload = basic_crypto.encrypt_message(str.encode(payload), str.encode(self.shared_server_key))

        return encrypted_payload

    def success_msg(self):
        """
        For use with message after successful login and sign-up,
        from server to client. Message in the encrypted form:
        {user_id:id}client-server-key

        Returns: tuple in the form [cipher.nonce, tag, encrypted message]
        """
        payload = f"user_id:{self.user_id}"
        encrypted_payload = basic_crypto.encrypt_message(str.encode(payload), str.encode(self.shared_server_key))

        return encrypted_payload


if __name__ == "__main__":
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
    req_nonce, req_tag, req_message = Message(msg_type="request", public_key=alice_public_key).generate_msg()
    res_nonce, res_tag, res_message = Message(msg_type="response", username=alice_username, password=alice_password,
                                              shared_server_key=alice_server_shared_key).generate_msg()
    suc_nonce, suc_tag, suc_message = Message(msg_type="success", user_id=alice_id,
                                              shared_server_key=alice_server_shared_key) \
        .generate_msg()

    MtS_nonce_1, MtS_tag_1, MtS_message_1 = Message(msg_type="message_to_server", msg_content="hello there",
                                              public_key=alice_public_key, recipient_id=bob_id,
                                              shared_server_key=alice_server_shared_key,
                                              shared_client_key=alice_bob_shared_key) \
        .generate_msg()
    MfS_nonce, MfS_tag, MfS_message = Message(msg_type="message_from_server",
                                              msg_content=[MtS_nonce_1, MtS_tag_1, MtS_message_1],
                                              user_id=alice_id, recipient_server_key=bob_server_shared_key,
                                              encrypted_payload=MtS_message_1) \
        .generate_msg()

    # decrypting tests
    sign_up_response_decrypt = basic_crypto.decrypt_message(
        res_nonce, res_tag, res_message, str.encode(alice_server_shared_key)
    ).decode()
    sign_up_success_decrypt = basic_crypto.decrypt_message(
        suc_nonce, suc_tag, suc_message, str.encode(alice_server_shared_key)
    ).decode()

    message_to_server_decrypt = basic_crypto.decrypt_message(
        MtS_nonce_1, MtS_tag_1, MtS_message_1, str.encode(alice_server_shared_key)
    ).decode()

    MtS_nonce_2, MtS_tag_2, MtS_message_2 = \
        [eval(item.strip()) for item in
         message_to_server_decrypt.split("payload:", 1)[1].strip().strip("(").strip(")").split(",", 2)]

    message_from_server_decrypt = basic_crypto.decrypt_message(
        MtS_nonce_2, MtS_tag_2, MtS_message_2, str.encode(alice_bob_shared_key)
    ).decode()

    print(f"Sign Up\n"
          f"Plaintext Request -  {req_message}\n"
          f"Decrypted Response - {sign_up_response_decrypt}\n"
          f"Decrypted Success -  {sign_up_success_decrypt}\n")

    print(f"Message\n"
          f"To Server - {message_to_server_decrypt_1}\n"
          f"To Client - {message_to_server_decrypt_2}\n")

