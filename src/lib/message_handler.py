import basic_crypto
import re

class MessageHandler():

    @classmethod
    def _get_message_contents_request(cls, message_bytes):
        parts = message_bytes.split(b',', 2)
    
        contents = {}
        contents['message_type'] = parts[0].split(b':')[1].decode()
        contents['public_key'] = parts[1].split(b':')[1].decode()

        return contents

    @classmethod
    def _get_message_contents_response(cls, message_bytes, key):
        _, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes.strip(b'{}').split(b', ', 4)]
 
        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        inner_parts = decrypted_payload.split(b',', 3)

        contents = {'message_type': inner_parts[0].split(b':')[1].decode(),
                    'username': inner_parts[1].split(b':')[1].decode(),
                    'password': inner_parts[2].split(b':')[1].decode()}
        return contents

    @classmethod
    def _get_message_contents_to_server(cls, message_bytes, key):
        _, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes.strip(b'{}').split(b', ', 4)]

        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        inner_parts = decrypted_payload.split(b',', 3)

        contents = {'message_type': inner_parts[0].split(b':', 1)[1].decode(),
                    'recipient_id': inner_parts[1].split(b':', 1)[1].decode(),
                    'timestamp:': inner_parts[2].split(b':', 1)[1].decode(),
                    'payload': inner_parts[3].split(b':', 1)[1].decode()}

        return contents


    @classmethod
    def get_message_contents(cls, message_bytes, key=None):
        message_type = message_bytes.split(b',', 1)[0].split(b':')[1]
        #print(f"message type: {message_type.decode()}")
        
        match message_type:
            case b"message_to_server":
                return cls._get_message_contents_to_server(message_bytes, key)
            case b"message_from_server":
                pass
            case b"request":
                return cls._get_message_contents_request(message_bytes)
            case b"response":
                return cls._get_message_contents_response(message_bytes, key)
            case b"success":
                pass

