import lib.basic_crypto as basic_crypto


class MessageHandler:

    @classmethod
    def _get_message_contents_request(cls, message_bytes):
        """
        Unpacks the contents of a `request` message
        Returns a dictionary with keys:
            'message_type'
            'public_key'
        """
        parts = message_bytes.split(b',', 2)

        contents = {
            'message_type': parts[0].split(b':')[1].decode(),
            'public_key': parts[1].split(b':')[1].decode()
        }

        return contents

    @classmethod
    def _get_message_contents_response(cls, message_bytes, key):
        """
        Unpacks the contents of a `response` message
        Returns a dictionary with keys:
            'message_type'
            'username'
            'password'
        Requires the client-server shared key
        """
        _, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes.strip(b'{}').split(b', ', 4)]

        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        inner_parts = decrypted_payload.split(b',', 3)

        contents = {'message_type': inner_parts[0].split(b':')[1].decode(),
                    'username': inner_parts[1].split(b':')[1].decode(),
                    'password': inner_parts[2].split(b':')[1].decode()
                    }
        return contents

    @classmethod
    def _get_message_contents_success(cls, message_bytes, key):
        """
        Unpacks the contents of a `success` message
        Returns a dictionary with keys:
            'message_type'
            'user_id'
            'username'
        Requires the client-server shared key
        """
        message_type, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes.strip(b'{}').split(b', ', 4)]

        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        parts = decrypted_payload.split(b',', 1)

        contents = {'message_type': message_type.decode(),
                    'user_id': parts[0].split(b':')[1].decode(),
                    'username': parts[1].split(b':')[1].decode()
                    }
        return contents

    @classmethod
    def _get_message_contents_to_server(cls, message_bytes, key):
        """
        Unpacks the contents of a `message_to_server` message
        Returns a dictionary with keys:
            'message_type'
            'recipient_id'
            'timestamp'
            'payload'
        Requires the sender-server shared key
        """
        message_bytes_1, message_bytes_2 = message_bytes.split(b"$$$", 2)

        _, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes_1.strip(b'{}').split(b', ', 4)]

        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        inner_parts = decrypted_payload.split(b',', 3)

        contents = {'message_type': inner_parts[0].split(b':', 1)[1].decode(),
                    'recipient_id': inner_parts[1].split(b':', 1)[1].decode(),
                    'timestamp': inner_parts[2].split(b':', 1)[1].decode(),
                    'payload': message_bytes_2
                    }

        return contents

    @classmethod
    def _get_message_contents_from_server(cls, message_bytes, server_key, client_key_dict):
        """
        Unpacks the contents of a `message_from_server` message
        Returns a dictionary with keys:
            'message_type'
            'sender_id'
            'timestamp'
            'payload'
        Requires the recipient-server shared key, along with a dictionary of client-client keys.
        """
        message_bytes_1, message_bytes_2 = message_bytes.split(b"$$$", 2)

        message_type, nonce_1, tag_1, encrypted_payload_1 = \
            [msg.split(b":", 1)[1] for msg in message_bytes_1.strip(b'{}').split(b', ', 4)]

        decrypted_payload_1 = basic_crypto.decrypt_message(nonce_1, tag_1, encrypted_payload_1, str.encode(server_key))
        sender_id, timestamp = [msg.split(b':', 1)[1] for msg in decrypted_payload_1.split(b', ', 2)]

        client_key = client_key_dict[sender_id.decode()]

        _, nonce_2, tag_2, encrypted_payload_2 = \
            [msg.split(b":", 1)[1] for msg in message_bytes_2.strip(b'{}').split(b', ', 4)]

        decrypted_payload_2 = basic_crypto.decrypt_message(nonce_2, tag_2, encrypted_payload_2, str.encode(client_key))

        contents = {'message_type': message_type.decode(),
                    'sender_id': sender_id.decode(),
                    'timestamp': timestamp.decode(),
                    'payload': decrypted_payload_2.decode()
                    }

        return contents

    @classmethod
    def _get_message_contents_client_key_request(cls, message_bytes, key):
        """
        Unpacks the contents of a `client_key_request` message
        Returns a dictionary with keys:
            'message_type'
            'id'
            'public_key'
        Requires the sender-server shared key.
        """
        message_type, nonce, tag, encrypted_payload = \
            [msg.split(b":", 1)[1] for msg in message_bytes.strip(b'{}').split(b', ', 4)]

        decrypted_payload = basic_crypto.decrypt_message(nonce, tag, encrypted_payload, str.encode(key))
        parts = decrypted_payload.split(b',', 2)

        contents = {'message_type': message_type.decode(),
                    'id': parts[0].split(b':')[1].decode(),
                    'public_key': parts[1].split(b':')[1].decode(),
                    }

        return contents

    @classmethod
    def get_message_contents(cls, message_bytes, server_key=None, client_key_dict=None):
        """
        Unpacks the contents of a given message
        Returns a dictionary of the message's contents
        """
        message_type = message_bytes.split(b',', 1)[0].split(b':')[1]
        # print(f"message type: {message_type.decode()}")

        if message_type == b"message_to_server":
            return cls._get_message_contents_to_server(message_bytes, server_key)
        elif message_type == b"message_from_server":
            return cls._get_message_contents_from_server(message_bytes, server_key=server_key,
                                                         client_key_dict=client_key_dict)
        elif message_type == b"request":
            return cls._get_message_contents_request(message_bytes)
        elif message_type == b"response":
            return cls._get_message_contents_response(message_bytes, server_key)
        elif message_type == b"success":
            return cls._get_message_contents_success(message_bytes, server_key)
        elif message_type == b"client_key_request":
            return cls._get_message_contents_client_key_request(message_bytes, server_key)
