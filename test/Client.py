import socket
import threading
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self, host='127.0.0.1', port=5004):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

    def connect_to_server(self):
        self.client_socket.connect((self.host, self.port))
        while True:
            choice = input("Do you want to (1) Signup or (2) Login? Enter 1 or 2: ")
            if choice == '1':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                self.client_socket.send(f"REGISTER,{username},{password}".encode())
                response = self.client_socket.recv(1024).decode()
                print(response)
                if response == "Registration successful.":
                    self.login(username, password)
                    break
            elif choice == '2':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                self.client_socket.send(f"LOGIN,{username},{password}".encode())
                response = self.client_socket.recv(1024).decode()
                print(response)
                if response == "Login successful.":
                    self.get_receiver_key(username)
                    break
            else:
                print("Invalid choice. Please try again.")

    def login(self, username, password):
        self.client_socket.send(f"LOGIN,{username},{password}".encode())
        response = self.client_socket.recv(1024).decode()
        print(response)
        if response == "Login successful.":
            self.get_receiver_key(username)
        else:
            print("Login failed.")
            self.client_socket.close()

    def get_receiver_key(self, username):
        recipient = input("Enter recipient's username: ")
        self.client_socket.send(f"REQUEST_CHAT,{recipient}".encode())
        response = self.client_socket.recv(1024).decode()
        if response.startswith("public key is here,"):
            encrypted_key_hex = response.split(",")[1]
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            private_key_pem = self.load_private_key(username)
            private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            server_public_key_pem = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())
            self.start_chat(username, recipient, server_public_key, private_key)
        else:
            print("Failed to get public key.")

    def start_chat(self, username, recipient, receiver_public_key, private_key):
        threading.Thread(target=self.receive_messages, args=(private_key,)).start()
        while True:
            message = input("Enter your message('q' to quit): ")
            if message.lower() == 'q':
                break
            self.send_message(recipient, username, message, receiver_public_key)

    def send_message(self, recipient, sender, message, receiver_public_key):
        encrypted_message = self.encrypt_message(message, receiver_public_key)
        full_message = f"SEND,{recipient},{base64.b64encode(encrypted_message).decode()}"
        self.client_socket.send(full_message.encode())

    def receive_messages(self, private_key):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024).decode()
                if encrypted_message.startswith("FROM"):
                    parts = encrypted_message.split(',', 2)
                    if len(parts) == 3:
                        _, sender, enc_message = parts
                        decrypted_message = self.decrypt_message(base64.b64decode(enc_message), private_key)
                        print(f"Message from {sender}: {decrypted_message}")
                    else:
                        print("Invalid message format.")
            except Exception as e:
                print(f"Error receiving message: {e}")

    def encrypt_message(self, message, public_key):
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self, encrypted_message, private_key):
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()

    def load_private_key(self, username):
        with open(f"private_keys/{username}_private_key.pem", "rb") as f:
            return f.read()

if __name__ == "__main__":
    client = Client()
