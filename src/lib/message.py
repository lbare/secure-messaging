import basic_crypto
import generate_hmac
import generate_keys
from datetime import datetime


def generate_timestamp():
    epoch_time = datetime(1970, 1, 1)
    current_time = datetime.now()
    delta = current_time - epoch_time
    return delta.total_seconds()


class Message:
    def __init__(self, msg_content, hmac, shared_client_key, shared_server_key,
                 msg_type=None, recipient_id=None):
        self.msg_content = msg_content
        self.hmac = hmac
        self.shared_client_key = shared_client_key
        self.shared_server_key = shared_server_key
        self.msg_type = msg_type
        self.recipient_id = recipient_id

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
        pass



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
