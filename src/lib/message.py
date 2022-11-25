import basic_crypto
import generate_hmac
import generate_keys
from datetime import datetime

"""
sender->server message
{message_type:send_message, recipient_id:id, timestamp:timestamp, payload:{hmac:hmac, timestamp:timestamp, message:message}p-pkey}sender-serverkey

server->recipient message
{sender_id:id, timestamp: timestamp, payload:{hmac:hmac, timestamp:timestamp, message:message}p-pkey}recipient

message_type {
	login_request
	delete_account_request
	send_message
}

"""


class Message:
    def __init__(self, msg_content, shared_key, private_key, msg_type=None, recipient_id=None):
        self.timestamp = self.generate_timestamp()
        self.msg_content = msg_content
        self.msg_type = msg_type
        self.recipient_id = recipient_id

    def client_to_server(self):
        pass

    def server_to_client(self):
        pass

    def generate_timestamp(self):
        epoch_time = datetime(1970, 1, 1)
        current_time = datetime.now()
        delta = current_time - epoch_time
        return delta.total_seconds()