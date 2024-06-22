import socket
import threading
import hashlib
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 5004

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

clients = {}
users_db = "users.txt"
Publickey_keys_db = "keys.txt"
private_keys_dir = "private_keys/"

if not os.path.exists(private_keys_dir):
    os.makedirs(private_keys_dir)

# Generate server's RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# Save server's public key to a file
def save_public_key(public_key, filename="server_public_key.pem"):
    with open(filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Generate and save the server's key pair
server_private_key = generate_rsa_key()
server_public_key = server_private_key.public_key()
save_public_key(server_public_key)

def load_users():
    users = {}
    try:
        with open(users_db, "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    username, password_hash, salt = line.strip().split(',')
                    users[username] = (password_hash, salt)
    except FileNotFoundError:
        pass
    return users

def save_user(username, password_hash, salt):
    with open(users_db, "a") as f:
        f.write(f"{username},{password_hash},{salt}\n")

def load_keys():
    keys = {}
    try:
        with open(Publickey_keys_db, "r") as f:
            lines = f.readlines()
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if line:  # Proceed only if the line is not empty
                    username, public_key_pm = line.split(',', 1)
                    pem_lines = [public_key_pm]
                    i += 1
                    while i < len(lines):
                        next_line = lines[i].strip()
                        pem_lines.append(next_line)
                        if 'END PUBLIC KEY' in next_line:
                            break
                        i += 1

                    public_key_pm = "\n".join(pem_lines)
                    public_key = serialization.load_pem_public_key(public_key_pm.encode(), backend=default_backend())
                    keys[username] = public_key
                i += 1

    except FileNotFoundError:
        print(f"File {Publickey_keys_db} not found.")
    except Exception as e:
        print(f"Error loading keys: {e}")

    return keys

def save_keys(username, public_key_pem):
    with open(Publickey_keys_db, "a") as f:
        f.write(f"{username},{public_key_pem.decode()}\n")

def save_private_key(username, private_key):
    with open(f"{private_keys_dir}{username}_private_key.pem", "wb") as f:
        f.write(private_key)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def handle_client(client_socket, address):
    user = None
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if data.startswith("REGISTER"):
                _, username, password = data.split(',')
                salt = os.urandom(16).hex()
                password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                users = load_users()
                if username in users:
                    client_socket.send("Username already exists.".encode())
                else:
                    save_user(username, password_hash, salt)
                    private_key_pem, public_key_pem = generate_keys()
                    save_private_key(username, private_key_pem)
                    save_keys(username, public_key_pem)
                    client_socket.send("Registration successful.".encode())
                    
            elif data.startswith("LOGIN"):
                _, username, password = data.split(',')
                users = load_users()
                if username in users:
                    stored_hash, salt = users[username]
                    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                    if stored_hash == password_hash:
                        client_socket.send("Login successful.".encode())
                        user = username
                        break
                    else:
                        client_socket.send("Invalid username or password.".encode())
                else:
                    client_socket.send("Invalid username or password.".encode())
        except Exception as e:
            print(f"Error during registration/login: {e}")
            client_socket.close()
            return

    clients[user] = client_socket
    print(f"{user} joined from {address}")

    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message.startswith("REQUEST_CHAT"):
                parts = message.split(',')
                if len(parts) == 2:
                    _, target_user = parts
                    print(f"Received chat request for {target_user} from {user}")
                    keys = load_keys()
                    if target_user in keys:
                        target_public_key = keys[target_user]
                        encrypted_key = target_public_key.encrypt(
                            server_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            ),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"Sending encrypted public key to {user}")
                        client_socket.send(f"public key is here,{encrypted_key.hex()}".encode())
                    else:
                        client_socket.send("User not found.".encode())
                else:
                    print("Invalid REQUEST_CHAT format.")
            elif message.startswith("SEND"):
                parts = message.split(',', 2)
                if len(parts) == 3:
                    _, recipient, enc_message = parts
                    send_message(f"FROM,{user},{enc_message}".encode(), recipient)
                else:
                    print("Invalid SEND format.")
            else:
                send_message(message.encode(), user)
        except Exception as e:
            print(f"Error during message handling: {e}")
            if user in clients:
                del clients[user]
                client_socket.close()
            print(f"Connection closed with {address} - username: {user}")
            break

def send_message(message, recipient):
    if recipient in clients:
        try:
            clients[recipient].send(message)
        except Exception as e:
            print(f"Error sending message to {recipient}: {e}")
            del clients[recipient]
    else:
        print(f"User {recipient} is not connected.")

def accept_clients():
    while True:
        try:
            client_socket, address = server_socket.accept()
            print(f"New connection from {address}")
            thread = threading.Thread(target=handle_client, args=(client_socket, address))
            thread.start()
        except Exception as e:
            print(f"Error accepting clients: {e}")

print("Server started!")
accept_thread = threading.Thread(target=accept_clients)
accept_thread.start()
