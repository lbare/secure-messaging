import hmac
import hashlib

def generate_new_hmac(key, message):
    """
    Returns an HMAC using the given key and message, using SHA-256.

    Parameters:
        - key: String
        - message: string
    """
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


if __name__ == "__main__":
    key = "abcd"
    message = "hello world"
    mac = generate_new_hmac(key, message)
    print(f"The MAC is {mac}")