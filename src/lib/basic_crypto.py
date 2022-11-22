from Crypto.Cipher import AES

# Takes in a message and key, both in bytes.
def encrypt_message(message, key):

    cipher = AES.new(key, AES.MODE_GCM)

    encrypted_message, tag = cipher.encrypt_and_digest(message)

    return cipher.nonce, tag, encrypted_message

# Takes nonce, tag, message, and key all in bytes.
def decrypt_message(nonce, tag, encrypted_message, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    try:
        decrypted_message = cipher.decrypt_and_verify(encrypted_message, tag)
        return decrypted_message
    except ValueError:
        raise ValueError("Message cannot be verified: Wrong key or message corrupted")
