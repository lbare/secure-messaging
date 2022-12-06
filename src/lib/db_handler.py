import sqlite3
import uuid
import src.lib.basic_crypto as basic_crypto
import time
import os


def sanitize(s_input: str):
    return "".join(c for c in s_input if c.isalnum())


class DatabaseError(Exception):
    pass


class DatabaseMessage:

    def __init__(self, message, timestamp, sender):
        self.message = message
        self.timestamp = timestamp
        self.sender = sender

    def __lt__(self, other):
        return other.timestamp > self.timestamp

    def __gt__(self, other):
        return other.timestamp < self.timestamp

    def __eq__(self, other):
        return other.timestamp == self.timestamp

    def __repr__(self):
        return f"{self.sender}:{self.message}"


class ClientDatabaseHandler:

    def __init__(self):
        self.database = None
        self.decrypter = None

    def _initialize_database(self, username):
        if self.database is not None:
            raise DatabaseError("Database connection already open, please log out before attempting to open another "
                                "connection")
        self.database = sqlite3.connect(f"{username}.db", check_same_thread=False)
        self.database.execute('''CREATE TABLE IF NOT EXISTS localUser(
            USERNAME TEXT PRIMARY KEY,
            PASSWORD_HASH BLOB,
            USER_ID INT,
            DECRYPTER BLOB,
            NONCE BLOB,
            TAG BLOB
        )''')
        self.database.execute('''CREATE TABLE IF NOT EXISTS contact(
            USERNAME TEXT PRIMARY KEY,
            ID INT
            )''')

    def _close_database(self):
        if self.database is None:
            return
        self.database.close()
        self.database = None
        self.decrypter = None

    def login(self, username, password):
        self._initialize_database(username)
        password_hash = basic_crypto.hash_password(password)
        for result in self.database.execute('''SELECT USER_ID, DECRYPTER, NONCE, TAG 
                                                FROM localUser WHERE PASSWORD_HASH = ?''', (password_hash,)):
            if len(result) == 0:
                return False
            user_id = result[0]
            decrypter_encrypted = result[1]
            decrypter_nonce = result[2]
            tag = result[3]
            self.decrypter = basic_crypto.decrypt_message(decrypter_nonce, tag, decrypter_encrypted,
                                                          basic_crypto.make_AES_key(password))
            return user_id

    def sign_up(self, username, password, user_id):
        self._initialize_database(username)
        plain_decrypter = basic_crypto.generate_key()
        nonce, tag, decrypter = basic_crypto.encrypt_message(plain_decrypter,
                                                             basic_crypto.make_AES_key(password))
        password_hash = basic_crypto.hash_password(password)
        self.database.execute('''INSERT INTO localUser(USERNAME, PASSWORD_HASH, USER_ID, DECRYPTER, NONCE, TAG)
            VALUES(?,?,?,?,?,?)''', (username, password_hash, user_id, decrypter, nonce, tag))

        self.database.commit()
        self._close_database()

    def logout(self):
        self._close_database()

    def add_contact(self, user_id, user_name):
        self.database.execute(f'''CREATE TABLE IF NOT EXISTS message{sanitize(str(user_id))}(
            TIMESTAMP INT PRIMARY KEY,
            SENDER TEXT,
            MESSAGE BLOB,
            NONCE BLOB,
            TAG BLOB)''')
        self.database.execute('''INSERT INTO contact(USERNAME, ID)
            VALUES(?,?)''', (user_name, user_id))
        self.database.commit()

    def add_message(self, user_id, message, timestamp, sender):
        nonce, tag, encrypted_message = basic_crypto.encrypt_message(message.encode(), self.decrypter)
        self.database.execute(f'''INSERT INTO message{sanitize(str(user_id))}(TIMESTAMP, SENDER, MESSAGE, NONCE, TAG)
            VALUES(?,?,?,?,?)''', (timestamp, sender, encrypted_message, nonce, tag))

        self.database.commit()

    def get_id(self, contact_name):
        user_id = None
        for contact in self.database.execute('''SELECT ID FROM contact WHERE USERNAME = ?''', (contact_name,)):
            user_id = contact[0]
        if user_id is None:
            return False
        return user_id

    def get_messages(self, contact_name):
        user_id = None
        messages = []
        for contact in self.database.execute('''SELECT ID FROM contact WHERE USERNAME = ?''', (contact_name,)):
            user_id = contact[0]
        if user_id is None:
            return False
        try:
            for entry in self.database.execute(f'''SELECT TIMESTAMP, SENDER, MESSAGE, NONCE, TAG
                                                    FROM message{sanitize(str(user_id))}'''):
                timestamp = entry[0]
                sender = entry[1]
                message_enc = entry[2]
                nonce = entry[3]
                tag = entry[4]
                message = basic_crypto.decrypt_message(nonce, tag, message_enc, self.decrypter).decode()
                messages.append(DatabaseMessage(message, timestamp, sender))

            messages.sort()
        except sqlite3.OperationalError:
            return []
        return messages

    def delete_conversation(self, contact_name):
        user_id = None
        for contact in self.database.execute('''SELECT ID FROM contact WHERE USERNAME = ?''', (contact_name,)):
            user_id = contact[0]
        if user_id is None:
            return False
        self.database.execute(f'''DROP TABLE IF EXISTS message{sanitize(str(user_id))}''')
        self.database.commit()
        return True

    def get_username(self, user_id):
        user_request = self.database.execute('''SELECT USERNAME FROM contact 
            WHERE ID = ? ''', (user_id,))
        username = None
        for i in user_request:
            username = i[0]
        return username

    def delete_user(self, username):
        self._close_database()
        os.remove(f"{username}.db")


class ServerDatabaseHandler:

    def __init__(self):
        self.database = None
        self.initialize_database()

    def initialize_database(self):
        self.database = sqlite3.connect('credentials.db', check_same_thread=False)
        self.database.execute('''CREATE TABLE IF NOT EXISTS users(
        ID INT PRIMARY KEY,
        USERNAME TEXT,
        PASSWORD_HASH BLOB
        )''')

    def insert_new_user(self, username, password):
        user_id = uuid.uuid4().int % 1000_0000_0000_0000
        password_hash = basic_crypto.hash_password(password)
        cursor = self.database.cursor()
        cursor.execute('''SELECT * FROM users 
            WHERE USERNAME = ?''', (username,))
        result = cursor.fetchone()
        if result:
            return False

        self.database.execute('''INSERT INTO users(ID, USERNAME, PASSWORD_HASH)
                VALUES(?,?,?)''', (user_id, username, password_hash))
        self.database.commit()
        return user_id

    def get_user(self, user_id):
        user_request = self.database.execute('''SELECT * FROM users 
            WHERE ID = ? ''', (user_id,))
        user = {}
        for i in user_request:
            user["user_id"] = i[0]
            user["username"] = i[1]
            user["password_hash"] = i[2]
        return user

    def get_user_by_name(self, username):
        user_request = self.database.execute('''SELECT ID FROM users 
            WHERE USERNAME = ? ''', (username,))
        user_id = None
        for i in user_request:
            user_id = i[0]
        return user_id

    def delete_user(self, user_id):
        self.database.execute('''DELETE FROM users WHERE ID = ?''', (user_id,))
        self.database.commit()

    def login(self, username, password):
        password_hash = basic_crypto.hash_password(password)
        user_request = self.database.execute('''SELECT * FROM users 
            WHERE USERNAME = ? AND PASSWORD_HASH = ? ''', (username, password_hash))
        user = {}
        for i in user_request:
            user["user_id"] = i[0]
            user["username"] = i[1]
            user["password_hash"] = i[2]
        return user


def test_sign_up():
    db = ClientDatabaseHandler()
    db.sign_up("Connor-Ebert", "password", 1)
    db.add_contact(2, "Bob")
    db.add_message(2, "Hi", int(time.time()), "Bob")
    db.logout()


def test_login_and_message_set_and_get():
    db = ClientDatabaseHandler()
    db.login("Connor-Ebert", "password")
    db.add_message(2, "hello", int(time.time()), "Me")
    time.sleep(1)
    db.add_message(2, "how", int(time.time()), "Bob")
    time.sleep(1)
    db.add_message(2, "h", int(time.time()), "Me")
    print(db.get_messages("Bob"))
    db.logout()


def server_test_login():
    db = ServerDatabaseHandler()
    user_id = db.insert_new_user("Connor", "password")
    print(db.get_user(user_id))
    print(db.login("Connor", "password"))


if __name__ == '__main__':
    test_login_and_message_set_and_get()
