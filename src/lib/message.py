import basic_crypto
import generate_hmac
import generate_keys
from datetime import datetime

message_type = {
    "login_request",
    "delete_account_request",
    "send_message"
}


def generate_timestamp():
    epoch_time = datetime(1970, 1, 1)
    current_time = datetime.now()
    delta = current_time - epoch_time
    return delta.total_seconds()


class Message:
    def __init__(self, msg_content, hmac, shared_client_key, shared_server_key,
                 msg_type=None, sender_id=None, recipient_id=None, encrypted_payload=None):
        self.msg_content = msg_content
        self.hmac = hmac
        self.shared_client_key = shared_client_key
        self.shared_server_key = shared_server_key
        self.msg_type = msg_type
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_payload = encrypted_payload

    def client_to_server(self):
        client_payload = f"hmac:{self.hmac}, " \
                         f"timestamp:{generate_timestamp()}, " \
                         f"message:{self.msg_content}"
        encrypted_client_payload = basic_crypto.encrypt_message(client_payload, self.shared_client_key)

        server_payload = f"message_type:{self.msg_type}, " \
                         f"recipient_id:{self.recipient_id}, " \
                         f"timestamp:{generate_timestamp()}" \
                         f"payload:{encrypted_client_payload}"
        encrypted_server_payload = basic_crypto.encrypt_message(server_payload, self.shared_server_key)

        return encrypted_server_payload

    def server_to_client(self):
        recipient_payload = f"sender_id:{self.sender_id}, " \
                            f"timestamp:{generate_timestamp()}" \
                            f"payload:{self.encrypted_payload}"
        return recipient_payload


if __name__ == "__main__":
    # Alice sending to Bob

    # user IDs
    alice_id = 123
    bob_id = 456

    # generate DH
    alice = generate_keys.generate_new_DH()
    bob = generate_keys.generate_new_DH()
    client = generate_keys.generate_new_DH()

    # generate private keys
    alice_private_key = alice.get_private_key()
    bob_private_key = bob.get_private_key()
    client_private_key = client.get_private_key()

    # generate shared keys
    alice_bob_shared_key = generate_keys.generate_shared_key(alice, bob)
    alice_server_shared_key = generate_keys.generate_shared_key(alice, client)
    bob_server_shared_key = generate_keys.generate_shared_key(bob, client)

    # message parameters
    msg_content_test = "hello there"
    hmac_test = generate_hmac.generate_new_hmac(alice_bob_shared_key, msg_content_test)
    msg_type_test = "send_message"
    sender_id_test = alice_id
    recipient_id_test = bob_id

    # create message
    msg_to_server = Message(msg_content_test,
                  hmac_test, alice_bob_shared_key, alice_server_shared_key,
                  msg_type=msg_type_test,
                  sender_id=sender_id_test, recipient_id=recipient_id_test)
    print(msg_to_server)



"""
sender->server message
{message_type:send_message, recipient_id:id, timestamp:timestamp, payload:
            {hmac:hmac, timestamp:timestamp, message:message}p-pkey
}sender-serverkey

server->recipient message
{sender_id:id, timestamp: timestamp, payload:
            {hmac:hmac, timestamp:timestamp, message:message}p-pkey
}recipient

message_type {
	login_request
	delete_account_request
	send_message
}
"""
