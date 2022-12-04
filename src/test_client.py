import socket
import threading
import lib.basic_crypto as basic_crypto

config = {}
incoming_data = None # Use global to store the incoming data so that it can be processed in the sending thread

with open('config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()

with open("credentials.txt") as f:
    username = f.readline().split(":")[1]


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print((config["ip"], int(config["port"])))
    s.connect((config["ip"], int(config["port"])))
    s.send(username.encode())
    recv_thread = threading.Thread(target=recv, args=[s])
    recv_thread.start()

    global incoming_data
    while 1:
        msg = input()
        user = "Test_id"
        data = f"{user}:{msg}"
        s.send(data.encode())


def recv(s):
    global incoming_data
    while 1:
        data = s.recv(1024).decode()
        if not data:
            break
        incoming_data = data
        print(data)


# Takes socket, username, password, and the client server key.
# Sends the username and password to the server
# Returns if successful or not
def handle_signup_process(s, username, password, client_server_key):
    response_message = "{username:" + username + ", password:" + password + "}"

    # Encrypt response message
    encrypted_response_message = basic_crypto.encrypt_message(response_message, client_server_key)
    msg = "{message_type:sign_up, nonce:" + encrypted_response_message[0] + ", tag:" + encrypted_response_message[1] + ", user_id:" + encrypted_response_message[2]+"}"
    s.send(msg.encode())

    # Timeout for 5 seconds to wait for response
    s.settimeout(5)

    # Need a better way to check if the message is the response
    # Threading is causing an issue here.
    # Parse Data for message type, need to decrypt but we having a parsing tool atn.
    message_type = incoming_data.get_message_type()

    if message_type == "response":
        # Do something with user ID?
        incoming_data.get_user_id()
        return True

    return False


if __name__ == '__main__':
    main()
