import socket
import threading

config = {}

with open('../config-file.txt') as f:
    for i in f.readlines():
        data = i.split(":")
        config[data[0]] = data[1].strip()

with open("../credentials.txt") as f:
    username = f.readline().split(":")[1]


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print((config["ip"], int(config["port"])))
    s.connect((config["ip"], int(config["port"])))
    s.send(username.encode())
    recv_thread = threading.Thread(target=recv, args=[s])
    recv_thread.start()
    while 1:
        data = input()
        s.send(data.encode())


def recv(s):
    while 1:
        data = s.recv(1024).decode()
        if not data:
            break
        print(data)


if __name__ == '__main__':
    main()
